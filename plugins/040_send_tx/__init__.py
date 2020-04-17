"""
Plugin

Send TX plugin
(BIS, Message, Token, RAW...)

This plugin is a generic low level plugin.
The key to use is given by the caller, so this plugin alone is not a security risk.

It allows any other plugin to insert a tx into the node mempool.

For now, it uses the local mempool (has to be on disk mempool, not ram)
or the local socket link.
Future versions could use the waller servers api.

Requires 035_socket_client plugin.
TODO: add that require mechanism into plugins init
(or at least require presence of a list of hook, the impl. may vary, or be provided by different packages)
"""

import base64
import json
import sqlite3
import sys
import threading
import time
from os import path

from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

__version__ = '0.0.5'


MANAGER = None

# This is the default mempool location, will be updated from config.
MEMPOOL_PATH = ''
MEMPOOL_CON = None


SQL_INSERT_TX = "INSERT INTO transactions (timestamp, address, recipient, amount, " \
                "signature, public_key, operation, openfield, mergedts) " \
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"

MEMPOOL_LOCK = threading.Lock()


def action_init(params):
    global MANAGER
    try:
        MANAGER = params['manager']
        init_mempool()
        MANAGER.app_log.warning("Init Send TX Plugin")
    except:
        # Better ask forgiveness than permission
        pass


def keys_load_new(keyfile="wallet.der"):
    # Import keys - This is a helper function
    # DUP from essentials
    with open (keyfile, 'r') as keyfile:
        wallet_dict = json.load (keyfile)
    private_key_readable = wallet_dict['Private Key']
    public_key_readable = wallet_dict['Public Key']
    address = wallet_dict['Address']
    try:
        key = RSA.importKey(private_key_readable)
        # unencrypted
        encrypted = False
        unlocked = True
    except:
        encrypted = True
        unlocked = False
        key = None
    if (len(public_key_readable)) != 271 and (len(public_key_readable)) != 799:
        raise ValueError("Invalid public key length: {}".format(len(public_key_readable)))
    public_key_hashed = base64.b64encode(public_key_readable.encode('utf-8')).decode("utf-8")
    keys = ('key', 'public_key_readable', 'private_key_readable', 'encrypted', 'unlocked', 'public_key_hashed', 'address')
    return dict(zip(keys, (key, public_key_readable, private_key_readable, encrypted, unlocked, public_key_hashed, address)))


def format_transaction(timestamp: float, address: str, recipient: str, amount: int, operation: str, openfield: str):
    """
    Returns the formatted tuple to use as transaction part and to be signed
    This exact formatting is MANDATORY - We sign a char buffer where every char counts.
    """
    str_timestamp = '%.2f' % timestamp
    str_amount = '%.8f' % float(amount)
    transaction = (str_timestamp, address, recipient, str_amount, operation, openfield)
    return transaction


def stringify_transaction(timestamp: float, address: str, recipient: str, amount: int, operation: str, openfield: str):
    """Formats the transaction items into the string buffer to be signed"""
    transaction = format_transaction(timestamp, address, recipient, amount, operation, openfield)
    return str(transaction).encode()


def sign_rsa(timestamp: float, address: str, recipient: str, amount: int, operation: str, openfield: str, key):
    # Sign with key - This is a helper function
    # Returns the encoded sig as a string
    as_string = stringify_transaction(timestamp, address, recipient, amount, operation, openfield)
    print("As String", as_string)
    h = SHA.new(as_string)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    signature_enc = base64.b64encode(signature)
    verifier = PKCS1_v1_5.new(key)
    if verifier.verify(h, signature):
        return signature_enc.decode("utf-8")
    else:
        return False


def filter_load_custom_keys(wallet_list):
    """
    Gets a list of wallet files location, and loads the matching keys into the related dicts.
    New wallet format only.
    Duplicate code from essentials
    """
    for wallet in wallet_list:
        keys = keys_load_new(wallet)
        if keys.get('encrypted', True):
            # not loaded or encrypted
            wallet_list[wallet] = {'loaded': False}
        else:
            wallet_list[wallet] = keys
            wallet_list[wallet]['loaded'] = True
    return wallet_list


def filter_sign_tx(tx_dict):
    """
    Signs a tx with provided wallet
    """
    if not tx_dict['wallet']:
        MANAGER.app_log.error("Error: sign_tx needs a wallet")
        return
    if not tx_dict['wallet']['loaded']:
        MANAGER.app_log.error("Error: sign_tx wallet not loaded")
        return
    if not tx_dict.get('address', False):
        MANAGER.app_log.error("Error: sign_tx no address")
        return
    if tx_dict['wallet']['address'] != tx_dict['address']:
        MANAGER.app_log.error("Error: sign_tx - wallet does not match sender address")
        return
    if not tx_dict.get('timestamp', False):
        tx_dict['timestamp'] = time.time()
    if not tx_dict.get('operation', False):
        tx_dict['operation'] = ''
    # add the pubkey
    tx_dict['public_key'] = tx_dict['wallet']['public_key_hashed']
    # Now sign
    tx_dict['signature'] = sign_rsa(tx_dict['timestamp'], tx_dict['address'], tx_dict['recipient'],
                                    tx_dict['amount'], tx_dict['operation'], tx_dict['openfield'],
                                    tx_dict['wallet']['key'])
    return tx_dict


def filter_send_tx_db(tx_dict):
    """
    Insert a signed tx into the local mempool db
    WARNING: since it's a direct insert, we have no feedback on the validity of the insert
    # TODO: if tx is not signed and we have a wallet, sign
    """
    if not tx_dict.get('signature', False):
        MANAGER.app_log.error("Error: send_tx not signed")
        return

    str_timestamp = '%.8f' % tx_dict['timestamp']
    str_amount = '%.8f' % float(tx_dict['amount'])

    params = (str_timestamp, tx_dict['address'], tx_dict['recipient'], str_amount,  tx_dict['signature'],
              tx_dict['public_key'], tx_dict['operation'], tx_dict['openfield'], int(time.time()))
    sql_mempool(SQL_INSERT_TX, params, action="_execute")
    sql_mempool(SQL_INSERT_TX, action="commit")

    tx_dict['result'] = 'N/A'

    return tx_dict


def filter_send_tx(tx_dict):
    """
    Sends the signed tx to the local host via a mpinsert message, adds the answer in the result
    # TODO: if tx is not signed and we have a wallet, sign
    # TODO: allow list of txs in one go? (node does accept, may be slightly faster)
    """
    if not tx_dict.get('signature', False):
        MANAGER.app_log.error("Error: send_tx not signed")
        return

    str_timestamp = '%.8f' % tx_dict['timestamp']
    str_amount = '%.8f' % float(tx_dict['amount'])

    # Assemble tx list
    data = [[str_timestamp, tx_dict['address'], tx_dict['recipient'], str_amount,  tx_dict['signature'],
             tx_dict['public_key'], tx_dict['operation'], tx_dict['openfield']]]
    # Send to local host
    try:
        command = {"command": "mpinsert", "params": [data]}
        # Sign that tx - Will add the timestamp if absent
        MANAGER.execute_filter_hook('native_command', command, first_only=True)
        tx_dict['result'] = command.get('result', 'N/A')
    except:
        tx_dict['result'] = 'TimeOut'

    return tx_dict


def init_mempool():
    global MEMPOOL_CON
    global MEMPOOL_PATH
    MEMPOOL_PATH = MANAGER.config.mempool_path
    # TODO: check that config has mempool_ram set to False
    if not path.isfile(MEMPOOL_PATH):
        MANAGER.app_log.error("Error <{}> not found".format(MEMPOOL_PATH))
        # We still are in mono-thread mode, we can die.
        sys.exit()
    try:
        MEMPOOL_CON = sqlite3.connect(MEMPOOL_PATH, timeout=10)
    except Exception as e:
        MANAGER.app_log.error("Error <{}> connecting to mempool {}".format(e, MEMPOOL_PATH))
        # We still are in mono-thread mode, we can die.
        sys.exit()


# TODO: appears in 2 plugins, include as part as manager instead?
def sql_mempool(sql='', params=None, action='_execute'):
    """Safely _execute the request. Lock is required because could be called from different threads."""
    with MEMPOOL_LOCK:
        if action == 'commit':
            MEMPOOL_CON.commit()
            return

        if params:
            res = MEMPOOL_CON.execute(sql, params)
        else:
            res = MEMPOOL_CON.execute(sql)

        if action == 'fetchone':
            res = res.fetchone()
        if action == 'fetchall':
            res = res.fetchall()

        return res


def action_status(status):
    """
    Temp hook to check the mempool connection works
    """
    # txcount = sql_mempool("SELECT COUNT(*) FROM transactions", action="fetchone")[0]
    # MANAGER.app_log.warning("Mempool has {} entries".format(txcount))
