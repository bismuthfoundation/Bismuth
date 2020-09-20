"""
Regnet specific functions and settings
"""

import base64
import functools
import math
import os
import sqlite3
import sys
import time
from hashlib import sha224
from random import getrandbits
from typing import List
from typing import TYPE_CHECKING

# from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA
from Cryptodome.Signature import PKCS1_v1_5

from libs import mempool as mp, connections, mining_heavy3 as mining

if TYPE_CHECKING:
    from libs.node import Node
    from libs.dbhandler import DbHandler

# fixed diff for regnet
REGNET_DIFF = 16

REGNET_PORT = 3030

REGNET_DB = ""
REGNET_INDEX = ""

SQL_INDEX = ["CREATE TABLE aliases (block_height INTEGER, address, alias)",
             "CREATE TABLE tokens (block_height INTEGER, timestamp, token, address, recipient, txid, amount INTEGER)" ]

# TODO EGG_EVO: legacy structure is hardcoded here
SQL_LEDGER = ["CREATE TABLE misc (block_height INTEGER PRIMARY KEY, difficulty TEXT)",

              "CREATE TABLE transactions (block_height INTEGER, timestamp NUMERIC, address TEXT, recipient TEXT, \
              amount NUMERIC, signature TEXT, public_key TEXT, block_hash TEXT, fee NUMERIC, reward NUMERIC, \
              operation TEXT, openfield TEXT)",

              "CREATE INDEX IF NOT EXISTS `Block Height Index` ON `transactions` (`block_height`)",

              "INSERT INTO transactions (openfield, operation, reward, fee, block_hash, public_key, signature, \
              amount, recipient, address, timestamp, block_height) \
              VALUES ('genesis', 1, 1, 0, '7a0f384876aca3871adbde8622a87f8b971ede0ed8ee10425e3958a1', \
              '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKvLTbDx85a1ugb/6xMMhVOq6U\n2GeYT8+Iq2z9FwIMR40l2ttGqNK7varNccFLIu8Kn4ogDQs3WSWQCxNkhZh/FqzF\nYYa3/ItPPfzrXqgajwD8q4Zt4Ymjt8+2BkImPjjFNkuTQIz2Iu3yFqOIxLdjMw7n\nUVu9tFPiUkD0VnDPLQIDAQAB\n-----END PUBLIC KEY-----', \
              'DKiWVr+GQHrsEUlu3qEQnsB5rznU4Is7RFLnPmHM1grobiUFHup0kSWiN83gBkNS9LgE57RXUEJvxMKc+9hIAzYE8EwGtO3RsXxkqPTT1v19CguN0iqE4nIM8Bur53/Djs5a1bH/R8EMersemZY1bDJ4jTeeba6yqFxmevGk/gw=', \
              0, '4edadac9093d9326ee4b17f869b14f1a2534f96f9c5d7b48dc9acaed', 'genesis', 1493640955.47, 1);",

              "INSERT INTO misc (difficulty, block_height) VALUES ({},1)".format(REGNET_DIFF)]


SQL_LEDGER_V2 = ["CREATE TABLE misc (block_height INTEGER PRIMARY KEY, difficulty TEXT)",

                 "CREATE TABLE IF NOT EXISTS `transactions` (`block_height` INTEGER, "
                 "`timestamp` NUMERIC, `address` TEXT, `recipient` TEXT, "
                 "`amount` INTEGER, `signature` BINARY, `public_key` BINARY, "
                 "`block_hash` BINARY, `fee` INTEGER, `reward` INTEGER,"
                 "`operation` TEXT, `openfield` TEXT)",

                 "CREATE INDEX IF NOT EXISTS `Block Height Index` ON `transactions` (`block_height`)",

                 "INSERT INTO transactions (openfield, operation, reward, fee, block_hash, public_key, signature, \
                 amount, recipient, address, timestamp, block_height) \
                 VALUES ('genesis', 1, 1, 0, x'7a0f384876aca3871adbde8622a87f8b971ede0ed8ee10425e3958a1', \
                 x'00', \
                 x'00', \
                 0, '4edadac9093d9326ee4b17f869b14f1a2534f96f9c5d7b48dc9acaed', 'genesis', 1493640955.47, 1);",

                 "INSERT INTO misc (difficulty, block_height) VALUES ({},1)".format(REGNET_DIFF)
                 ]

HASHCOUNT = 10


# Max number of tx to embed per block.
TX_PER_BLOCK = 2


# Do not edit below, it's fed by node.py

ADDRESS = 'This is a fake address placeholder for regtest mode only'
KEY = None
PRIVATE_KEY_READABLE = 'matching priv key'
PUBLIC_KEY_B64ENCODED = 'matching pub key b64'


def sql_trace_callback(log, id_str, statement):
    line = f"SQL[{id_str}] {statement}"
    log.warning(line)


def generate_one_block(blockhash: str, mempool_txs: List[tuple], node: "Node", db_handler: "DbHandler") -> str:
    """BEWARE: mempool_txs is a list of legacy tuple, not Transaction objects"""
    try:
        if not blockhash:
            node.logger.app_log.warning("Bad blockhash")
            return
        diff_hex = math.floor((REGNET_DIFF / 8) - 1)
        mining_condition = blockhash[0:diff_hex]
        while True:
            try_arr = [('%0x' % getrandbits(32)) for i in range(HASHCOUNT)]
            for j in range(100):
                seed = ('%0x' % getrandbits(128 - 32))
                prefix = ADDRESS + seed
                possibles = [nonce for nonce in try_arr if
                             mining_condition in (mining.anneal3(
                                 mining.MMAP,
                                 int.from_bytes(sha224((prefix + nonce + blockhash).encode("utf-8")).digest(), 'big')))]
                if possibles:
                    nonce = seed + possibles[0]
                    node.logger.app_log.warning("Generate got a block in {} tries len {}".format(j, len(possibles)))
                    # assemble block with mp data
                    txs = []
                    for n in range(TX_PER_BLOCK):
                        if not len(mempool_txs):
                            break
                        txs.append(mempool_txs.pop(0))  # .to_tuple()) - mempool tx are tuple already
                        # TODO: EGG_EVO BEWARE ! Should be converted to use transaction object,
                        # but still relies on legacy format afterward.
                        # Sticking with legacy tuple
                        # Will need rework, regnet maybe could only use the new db format (it's volatile anyway)
                    block_send = []
                    removal_signature = []
                    for mpdata in txs:
                        transaction = (
                            str(mpdata[0]), str(mpdata[1][:56]), str(mpdata[2][:56]), '%.8f' % float(mpdata[3]),
                            str(mpdata[4]), str(mpdata[5]), str(mpdata[6]),
                            str(mpdata[7]))  # create tuple
                        # node.logger.app_log.warning transaction
                        block_send.append(transaction)  # append tuple to list for each run
                        removal_signature.append(str(mpdata[4]))  # for removal after successful mining
                    # claim reward
                    block_timestamp = f"{time.time():.2f}"
                    """block_timestamp = '%.2f' % time.time()
                    transaction_reward = str((str(block_timestamp), str(ADDRESS[:56]), str(ADDRESS[:56]),
                                          '%.8f' % float(0), "0", str(nonce)))  # only this part is signed!
                    """
                    transaction_reward = str((block_timestamp, ADDRESS[:56], ADDRESS[:56], f"{0:.8f}", "0", str(nonce)))
                    # node.logger.app_log.warning transaction_reward
                    node.logger.app_log.warning(f"Buffer to sign: {transaction_reward}")
                    tx_hash = SHA.new(transaction_reward.encode("utf-8"))
                    signer = PKCS1_v1_5.new(KEY)
                    signature = signer.sign(tx_hash)
                    signature_enc = base64.b64encode(signature)

                    if signer.verify(tx_hash, signature):
                        node.logger.app_log.warning("Signature valid")
                        # mining reward tx
                        block_send.append((str(block_timestamp), str(ADDRESS[:56]), str(ADDRESS[:56]),
                                           '%.8f' % float(0), str(signature_enc.decode("utf-8")),
                                           str(PUBLIC_KEY_B64ENCODED.decode("utf-8")), "0", str(nonce)))
                        """
                        block_send.append((block_timestamp, str(ADDRESS[:56]), str(ADDRESS[:56]),
                                           '%.8f' % float(0), str(signature_enc.decode("utf-8")),
                                           str(PUBLIC_KEY_B64ENCODED.decode("utf-8")), "0", str(nonce)))
                        """
                        node.logger.app_log.warning("Block to send: {}".format(block_send))
                    # calc hash

                    new_hash = node.digest_block(node, [block_send], None, 'regtest',  db_handler)
                    # post block to self or better, send to db to make sure it is. when we add the next one?
                    # use a link to the block digest function
                    # embed at mot TX_PER_BLOCK txs from the mp
                    return new_hash

    except Exception as e:
        node.logger.app_log.warning(e)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        node.logger.app_log.warning(exc_type, fname, exc_tb.tb_lineno)


def command(sdef, data: str, blockhash: "str", node: "Node", db_handler: "DbHandler") -> None:
    try:
        node.logger.app_log.warning("Regnet got command {}".format(data))
        if data == 'regtest_generate':
            how_many = int(connections.receive(sdef))
            node.logger.app_log.warning("regtest_generate {} {}".format(how_many, blockhash))
            # mempool_txs = mp.mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)
            mempool_txs = mp.MEMPOOL.transactions_to_send()  # This is a list of tuples, legacy format, 9 items
            for i in range(how_many):
                blockhash = generate_one_block(blockhash, mempool_txs, node, db_handler)
            connections.send(sdef, 'OK')
    except Exception as e:
        node.logger.app_log.warning(e)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        node.logger.app_log.warning(exc_type, fname, exc_tb.tb_lineno)


def init(node: "Node", app_log, trace_db_calls: bool=False) -> None:
    global REGNET_DB, REGNET_INDEX
    REGNET_DB = node.config.get_ledger_db_path()
    REGNET_INDEX = node.config.get_index_db_path()
    # Empty peers
    with open(node.peerfile, 'w') as f:
        f.write("{}")
    with open(node.peerfile_suggested, 'w') as f:
        f.write("{}")
    # empty files
    for remove_me in [REGNET_DB, REGNET_INDEX]:
        if os.path.exists(remove_me):
            os.remove(remove_me)
    # create empty index db
    with sqlite3.connect(REGNET_DB) as source_db:
        if trace_db_calls:
            source_db.set_trace_callback(functools.partial(sql_trace_callback, app_log, "REGNET-INIT"))
        if node.config.legacy_db:
            for request in SQL_LEDGER:
                source_db.execute(request)
        else:
            for request in SQL_LEDGER_V2:
                source_db.execute(request)
        source_db.commit()
    # create empty reg db
    with sqlite3.connect(REGNET_INDEX) as source_db:
        if trace_db_calls:
            source_db.set_trace_callback(functools.partial(sql_trace_callback, app_log, "REGNET-INIT-INDEX"))
        for request in SQL_INDEX:
            source_db.execute(request)
        source_db.commit()

    # Here, we do not have the keys info yet.
