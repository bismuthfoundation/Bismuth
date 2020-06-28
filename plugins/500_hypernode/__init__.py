"""
Plugin

Hypernode plugin

This plugin is intended to extend the node with features specifically needed by the HN companion.
"""


import ipaddress
import json
import os
import re
import sqlite3
from os import path
from hashlib import blake2b
from threading import Lock

from time import time, sleep
from typing import Union
from warnings import filterwarnings

from ipwhois import IPWhois
from polysign.signerfactory import SignerFactory

import base58

# ledger_queries is to be in the bismuth directory
# you can symlink in this dir for dev purposes and add it to "sources" in pycharm.
from ledger_queries import LedgerQueries, __version__ as ledger_queries_version

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from libs.plugins import PluginManager
# from warnings import resetwarnings


__version__ = "0.1.4"


MANAGER: "PluginManager" = None

VERBOSE = True  # False in production, set to True for first version.

# Has to be sync with matching params from HN - Do not edit
ORIGIN_OF_TIME = 1534716000  # Real Origin: August 20
POS_SLOT_TIME_MIN = 3
POS_SLOT_TIME_SEC = POS_SLOT_TIME_MIN * 60
MAX_ROUND_SLOTS = 19
END_ROUND_SLOTS = 1
ROUND_TIME_SEC = POS_SLOT_TIME_SEC * (MAX_ROUND_SLOTS + END_ROUND_SLOTS)

SQL_GET_COLOR_LIST = (
    "SELECT openfield FROM transactions WHERE address = ? and operation = ? "
    "ORDER BY block_height DESC LIMIT 1"
)

COLORED = dict()
COLORS = [
    "white",
    "cloud",
    "brown",
    "bismuth",
    "gray",
    "blue",
    "red",
    "orange",
    "black",
    "rainbow",
    "bootstrap",
]
"""
Some colors are just reserved, not used yet.
white: whitelist for specific ips that could be catched by global blacklists
cloud: large cloud operators been seen to operate large number of fake or malicious nodes
brown: nodes - non miners - been seen to ask for exagerated rollbacks. Either malicious or badly configured.
bismuth: known miners ip
gray: outdated nodes, unmaintained...
blue:
red:
orange:
black: blacklist for real evil nodes
rainbow: no ip list, but some global config params that can be globally tuned without asking for posnet or code update.
bootstrap: urls of HN bootstrap file
"""

POW_CONTROL_ADDRESS = "cf2562488992997dff3658e455701589678d0e966a79e2a037cbb2ff"

UPDATED = False

# from config
HNROUNDS_DIR = ""
HNCOLORED = "colored.json"

# from config
LEDGER_PATH = ""
POWSTATUS_PATH = ""

# Convention is to have a prefix ending in _ , so prefix and subsequent commands are easily readable.
# Take care not to overload an existing command
PREFIX = "HN_"

filterwarnings(action="ignore")

CACHE = '{"127.0.0.1": "localhost", "62.112.10.156": "worldstream, nl", "95.179.153.13": "as-choopa - choopa, llc, us", "51.15.234.210": "as12876, fr", "91.121.77.179": "ovh, fr", "185.125.46.56": "itgrad, ru", "34.231.198.116": "amazon-aes - amazon.com, inc., us", "149.28.46.106": "as-choopa - choopa, llc, us", "107.191.39.23": "as-choopa - choopa, llc, us", "31.31.75.71": "wedos, cz", "163.172.222.163": "as12876, fr", "212.24.111.139": "rackray uab rakrejus, lt", "51.15.46.90": "as12876, fr", "51.15.122.148": "as12876, fr", "199.247.0.43": "as-choopa - choopa, llc, us", "204.12.231.62": "wii-kc - wholesale internet, inc., us", "208.167.245.204": "as-choopa - choopa, llc, us", "51.15.228.170": "as12876, fr", "91.121.87.99": "ovh, fr", "46.101.186.35": "digitalocean-asn - digitalocean, llc, us", "85.214.27.126": "strato strato ag, de", "188.165.199.153": "ovh, fr", "199.247.23.214": "as-choopa - choopa, llc, us", "194.19.235.82": "telialatvija, lv", "51.15.47.212": "as12876, fr", "149.28.120.120": "as-choopa - choopa, llc, us", "176.31.245.46": "ovh, fr", "198.245.62.30": "ovh, fr", "159.69.147.99": "hetzner-as, de", "45.76.15.224": "as-choopa - choopa, llc, us", "51.15.201.253": "as12876, fr", "159.69.4.64": "hetzner-as, de", "51.15.118.29": "as12876, fr", "78.28.227.89": "telialatvija, lv", "51.15.211.92": "as12876, fr", "35.197.74.239": "google - google llc, us", "35.237.184.166": "google - google llc, us", "52.47.144.143": "amazon-02 - amazon.com, inc., us", "149.28.245.191": "as-choopa - choopa, llc, us", "46.105.43.213": "ovh, fr", "51.15.225.223": "as12876, fr", "35.153.128.15": "amazon-aes - amazon.com, inc., us", "140.82.11.77": "as-choopa - choopa, llc, us", "13.57.46.55": "amazon-02 - amazon.com, inc., us", "159.69.147.101": "hetzner-as, de", "46.174.51.94": "rsmedia-as, ru", "66.70.181.150": "ovh, fr", "217.163.23.242": "as-choopa - choopa, llc, us", "159.89.22.201": "digitalocean-asn - digitalocean, llc, us", "80.211.190.140": "aruba-asn, it", "109.92.6.40": "telekom-as, rs", "51.15.254.16": "as12876, fr", "51.15.95.155": "as12876, fr", "45.63.8.89": "as-choopa - choopa, llc, us", "94.209.218.82": "ziggo ziggo b.v., nl", "178.62.68.118": "digitalocean-asn - digitalocean, llc, us", "163.172.139.156": "as12876, fr", "51.15.90.15": "as12876, fr", "217.23.4.201": "worldstream, nl", "204.12.231.58": "wii-kc - wholesale internet, inc., us", "163.172.166.207": "as12876, fr", "163.172.161.7": "as12876, fr", "212.91.114.195": "vipnet-as 3g/gsm and internet service provider, hr", "188.162.228.229": "mf-dv-as, ru", "109.190.174.238": "ovh-telecom, fr", "50.101.34.205": "bacom - bell canada, ca", "80.240.26.221": "as-choopa - choopa, llc, us", "85.217.170.190": "belcloud, bg", "85.10.207.156": "hetzner-as, de", "66.190.41.128": "charter-net-hky-nc - charter communications, us", "35.227.160.215": "google - google llc, us", "149.28.34.231": "as-choopa - choopa, llc, us", "198.27.102.167": "ovh, fr", "195.13.183.65": "apollo-as latvia, lv", "159.69.12.98": "hetzner-as, de", "83.84.166.127": "ziggo ziggo b.v., nl", "34.241.102.43": "amazon-02 - amazon.com, inc., us", "37.230.137.254": "rsmedia-as, ru", "45.77.72.149": "as-choopa - choopa, llc, us", "149.28.53.219": "as-choopa - choopa, llc, us", "34.244.97.229": "amazon-02 - amazon.com, inc., us", "58.137.188.135": "csloxinfo-as-ap cs loxinfo public company limited, th", "163.172.168.43": "as12876, fr", "34.240.96.75": "amazon-02 - amazon.com, inc., us", "178.251.109.240": "dataline-as, ua", "95.220.87.52": "ti-as moscow, russia, ru", "149.28.122.54": "as-choopa - choopa, llc, us", "51.15.85.104": "as12876, fr", "50.237.104.40": "comcast-7922 - comcast cable communications, llc, us", "47.104.24.116": "cnnic-alibaba-cn-net-ap hangzhou alibaba advertising co.,ltd., cn", "40.115.65.119": "microsoft-corp-msn-as-block - microsoft corporation, us", "45.63.43.83": "as-choopa - choopa, llc, us", "217.69.10.27": "as-choopa - choopa, llc, us", "119.4.240.251": "china169-backbone china unicom china169 backbone, cn", "192.99.34.19": "ovh, fr", "193.152.190.194": "telefonica_de_espana, es", "194.25.1.2": "dtag internet service provider operations, de", "71.231.249.117": "comcast-7922 - comcast cable communications, llc, us", "99.234.90.241": "rogers-communications - rogers communications canada inc., ca", "198.27.232.254": "as-sonictelecom - sonic telecom llc, us", "176.74.212.129": "get-no get norway, no", "45.77.178.35": "as-choopa - choopa, llc, us", "93.79.23.203": "volia-as, ua", "40.115.66.20": "microsoft-corp-msn-as-block - microsoft corporation, us", "31.129.67.122": "asdnepronet, ua", "24.134.1.89": "kabeldeutschland-as, de", "93.34.239.151": "fastweb, it", "92.60.225.190": "exenet-as, rs", "144.202.6.124": "as-choopa - choopa, llc, us", "59.110.226.26": "cnnic-alibaba-cn-net-ap hangzhou alibaba advertising co.,ltd., cn", "24.172.73.118": "scrr-11426 - time warner cable internet llc, us", "109.195.250.44": "cheb-as, ru", "82.94.183.179": "xs4all-nl amsterdam, nl", "95.179.137.32": "as-choopa - choopa, llc, us", "209.246.143.198": "as-choopa - choopa, llc, us", "51.255.168.67": "ovh, fr", "81.169.153.71": "strato strato ag, de", "195.24.154.50": "apexncc-as gagarina avenue, building 7, room 61, ru", "209.250.238.142": "as-choopa - choopa, llc, us", "145.239.149.71": "ovh, fr", "67.181.232.254": "comcast-7922 - comcast cable communications, llc, us", "46.216.193.94": "mtsby-as, by", "194.19.235.83": "telialatvija, lv", "159.69.147.56": "hetzner-as, de", "89.151.186.91": "rostelecom-as, ru", "167.114.129.139": "ovh, fr", "46.109.2.23": "apollo-as latvia, lv", "178.128.199.21": "digitalocean-asn - digitalocean, llc, us", "176.125.84.60": "ttk-rtl retail, ru", "108.61.117.70": "as-choopa - choopa, llc, us", "84.132.88.12": "dtag internet service provider operations, de", "209.250.237.31": "as-choopa - choopa, llc, us", "173.179.33.167": "videotron - videotron telecom ltee, ca", "109.236.83.141": "worldstream, nl", "18.184.255.105": "amazon-02 - amazon.com, inc., us", "185.144.100.58": "bandwidth-as, gb", "47.52.10.244": "cnnic-alibaba-cn-net-ap alibaba (china) technology co., ltd., cn", "47.95.123.145": "cnnic-alibaba-cn-net-ap hangzhou alibaba advertising co.,ltd., cn", "163.172.143.181": "as12876, fr", "217.37.63.250": "bt-uk-as btnet uk regional network, gb", "198.54.123.177": "namecheap-net - namecheap, inc., us", "51.15.37.127": "as12876, fr", "178.135.88.3": "ogeronet ogero telecom, lb", "88.27.19.97": "telefonica_de_espana, es", "89.40.0.254": "rackray uab rakrejus, lt", "5.9.151.175": "hetzner-as, de", "149.28.181.100": "as-choopa - choopa, llc, us", "99.130.59.50": "att-internet4 - at&t services, inc., us", "46.185.2.1": "ksnet-as, ua", "50.3.86.104": "serverhub-, de", "95.179.163.183": "as-choopa - choopa, llc, us", "34.192.6.105": "amazon-aes - amazon.com, inc., us", "159.89.22.207": "digitalocean-asn - digitalocean, llc, us", "108.170.1.134": "ssasn2 - secured servers llc, us", "45.77.6.146": "as-choopa - choopa, llc, us", "159.69.147.100": "hetzner-as, de", "142.93.243.200": "digitalocean-asn - digitalocean, llc, us", "162.213.123.200": "turnkey-internet - turnkey internet inc., us", "46.171.63.219": "tpnet, pl", "89.25.168.21": "tkpsa-as, pl", "79.133.151.125": "rostelecom-as, ru", "148.251.52.30": "hetzner-as, de", "185.206.146.219": "belcloud, bg", "178.63.21.152": "hetzner-as, de", "85.217.170.187": "belcloud, bg", "79.123.162.82": "ulaknet, tr", "85.217.170.113": "belcloud, bg", "94.156.35.6": "belcloud, bg", "5.104.175.50": "belcloud, bg", "94.156.35.223": "belcloud, bg", "94.156.35.111": "belcloud, bg", "185.177.59.152": "belcloud, bg", "91.92.136.130": "belcloud, bg", "94.156.35.150": "belcloud, bg", "185.203.117.44": "belcloud, bg", "185.206.145.85": "belcloud, bg", "85.217.171.9": "belcloud, bg", "91.92.136.22": "belcloud, bg", "91.92.136.112": "belcloud, bg", "5.104.175.112": "belcloud, bg", "91.92.128.156": "belcloud, bg", "185.206.147.64": "belcloud, bg", "91.92.128.46": "belcloud, bg", "94.156.128.71": "belcloud, bg", "185.177.59.161": "belcloud, bg", "185.203.118.56": "belcloud, bg", "5.104.175.55": "belcloud, bg", "94.156.189.200": "belcloud, bg", "34.231.80.215": "amazon-aes - amazon.com, inc., us", "212.73.150.90": "belcloud, bg", "94.156.144.5": "belcloud, bg", "142.93.93.4": "digitalocean-asn - digitalocean, llc, us", "80.240.18.114": "as-choopa - choopa, llc, us", "54.39.144.62": "ovh, fr", "178.128.150.29": "digitalocean-asn - digitalocean, llc, us", "209.182.233.16": "incero - incero llc, us", "212.204.162.14": "ziggo ziggo b.v., nl", "207.148.116.109": "as-choopa - choopa, llc, us", "46.101.189.137": "digitalocean-asn - digitalocean, llc, us", "98.167.99.23": "asn-cxa-all-cci-22773-rdc - cox communications inc., us", "31.135.145.81": "tcrs-as sumy, ukraine, ua", "194.146.191.198": "eurotel-as, ua", "84.42.23.120": "ctctver, ru", "90.189.147.122": "rostelecom-as, ru", "193.19.228.50": "iu-as general networks company, ua", "83.69.86.75": "kavkaz-transtelecom-as, ru", "5.165.130.93": "tver-as, ru", "45.32.115.135": "as-choopa - choopa, llc, us", "2.93.46.186": "corbina-as ojsc _vimpelcom_, ru", "178.135.29.124": "ogeronet ogero telecom, lb", "91.105.135.2": "zsttkas novosibirsk, russia, ru", "104.238.173.26": "as-choopa - choopa, llc, us", "95.90.191.147": "kabeldeutschland-as, de", "177.183.101.187": "claro s.a., br", "88.198.65.235": "hetzner-as, de", "108.61.166.237": "as-choopa - choopa, llc, us", "159.69.155.211": "hetzner-as, de", "79.159.36.63": "telefonica_de_espana, es", "31.135.154.250": "tcrs-as sumy, ukraine, ua", "88.0.120.127": "telefonica_de_espana, es", "177.216.158.64": "tim celular s.a., br", "94.253.254.192": "dcm-as vipnet d.o.o., hr", "178.135.90.15": "ogeronet ogero telecom, lb", "62.122.211.198": "asteis-as, ru", "46.216.194.147": "mtsby-as, by", "39.57.251.225": "pktelecom-as-pk pakistan telecom company limited, pk", "109.252.195.132": "asn-mgts-uspd, ru", "178.128.222.221": "digitalocean-asn - digitalocean, llc, us", "149.248.1.1": "as-choopa - choopa, llc, us", "159.89.10.229": "digitalocean-asn - digitalocean, llc, us", "47.32.232.17": "charter-net-hky-nc - charter communications, us", "188.166.118.218": "digitalocean-asn - digitalocean, llc, us", "109.166.137.126": "asn-orange-romania, ro", "159.89.123.247": "digitalocean-asn - digitalocean, llc, us", "178.135.225.182": "ogeronet ogero telecom, lb", "82.16.135.238": "ntl, gb", "104.225.219.242": "incero - incero llc, us", "139.59.25.152": "digitalocean-asn - digitalocean, llc, us", "113.161.230.70": "vnpt-as-vn vnpt corp, vn", "159.69.44.135": "hetzner-as, de", "45.32.17.36": "as-choopa - choopa, llc, us", "217.23.14.6": "worldstream, nl", "178.71.57.218": "asn-spbnit macro region north-west autonomous system, ru", "95.55.136.96": "asn-spbnit macro region north-west autonomous system, ru", "91.60.67.251": "dtag internet service provider operations, de", "39.57.187.226": "pktelecom-as-pk pakistan telecom company limited, pk", "86.5.209.208": "ntl, gb", "178.251.109.243": "dataline-as, ua", "39.57.193.116": "pktelecom-as-pk pakistan telecom company limited, pk", "83.219.146.118": "tis-dialog-as, ru", "105.101.33.61": "algtel-as, dz", "94.233.224.219": "rostelecom-as, ru", "70.27.245.79": "bacom - bell canada, ca", "79.152.225.102": "telefonica_de_espana, es", "188.163.89.162": "ksnet-as, ua", "46.216.194.88": "mtsby-as, by", "46.63.69.228": "x-city-as, ua", "189.150.198.126": "uninet s.a. de c.v., mx", "178.44.248.198": "rostelecom-as, ru", "185.135.194.111": "asn-m3net, pl", "83.52.164.149": "telefonica_de_espana, es", "178.135.80.181": "ogeronet ogero telecom, lb", "187.150.244.35": "uninet s.a. de c.v., mx", "194.33.77.116": "speednet-as, pl", "46.216.194.164": "mtsby-as, by", "178.218.102.6": "tinet-as, ru", "178.165.119.133": "citynet-as maxnet llc, ua", "78.26.144.110": "renome-as, ua", "91.60.74.210": "dtag internet service provider operations, de", "83.219.146.239": "tis-dialog-as, ru", "188.27.195.42": "rcs-rds 73-75 dr. staicovici, ro", "95.220.152.111": "ti-as moscow, russia, ru", "5.12.214.216": "rcs-rds 73-75 dr. staicovici, ro", "178.135.80.27": "ogeronet ogero telecom, lb", "45.33.8.142": "linode-ap linode, llc, us", "46.175.70.216": "mediana-as, ua", "95.71.170.84": "rostelecom-as, ru", "117.197.133.127": "bsnl-nib national internet backbone, in", "116.100.188.11": "viettel-as-vn viettel corporation, vn", "194.146.229.74": "tcrs-as sumy, ukraine, ua", "109.87.17.173": "triolan, ua", "188.129.88.11": "amis, hr", "171.240.236.27": "vietel-as-ap viettel group, vn", "110.171.135.21": "true-as-ap true internet co.,ltd., th", "223.237.33.198": "bharti-mobility-as-ap bharti airtel ltd. as for gprs service, in", "178.135.80.39": "ogeronet ogero telecom, lb", "171.239.106.168": "vietel-as-ap viettel group, vn", "139.59.91.47": "digitalocean-asn - digitalocean, llc, us", "178.135.90.224": "ogeronet ogero telecom, lb", "46.134.182.244": "tpnet, pl", "193.198.102.32": "carnet-as j.marohnica 5, 10000 zagreb, hr", "95.160.158.242": "vectranet-as al. zwyciestwa 253, 81-525 gdynia, poland, pl", "78.84.164.76": "apollo-as latvia, lv", "116.100.191.237": "viettel-as-vn viettel corporation, vn", "93.227.120.229": "dtag internet service provider operations, de", "46.216.194.232": "mtsby-as, by", "148.252.228.26": "metronetuk_m24seven, gb", "45.35.55.30": "as40676 - psychz networks, us", "178.135.64.193": "ogeronet ogero telecom, lb", "77.222.114.37": "intersvyaz-as 38-b, komsomolsky prospekt, ru", "81.202.133.168": "ono-as cableuropa - ono, es", "171.240.232.137": "vietel-as-ap viettel group, vn", "94.253.254.203": "dcm-as vipnet d.o.o., hr", "212.170.217.113": "telefonica_de_espana, es", "51.68.190.246": "ovh, fr", "87.110.160.76": "apollo-as latvia, lv", "78.3.121.41": "t-ht croatian telecom inc., hr", "51.15.211.156": "as12876, fr"}'

LEDGER_DB = False  # Global DB handler

ROUND_LOCK = Lock()


def init_colored():
    global COLORED
    try:
        with sqlite3.connect(LEDGER_PATH, timeout=30) as db:
            try:
                for color in COLORS:
                    res = db.execute(
                        SQL_GET_COLOR_LIST,
                        (POW_CONTROL_ADDRESS, "color:{}".format(color)),
                    )
                    result = res.fetchone()
                    if result:
                        result = result[0].strip().split(",")
                    else:
                        result = []
                    COLORED[color] = result
            except Exception as e:
                print(e)
    finally:
        # Failsafe if we can't read from chain
        if "cloud" not in COLORED:
            COLORED["cloud"] = ["amazon"]
        if "white" not in COLORED:
            COLORED["white"] = [
                "34.231.198.116",
                "18.184.255.105",
                "18.223.102.119",
                "13.58.108.209",
                "18.224.195.95",
                "18.225.1.235",
            ]
        with open(HNCOLORED, "w") as f:
            json.dump(COLORED, f)


def action_init(params):
    global MANAGER
    global DESC
    try:
        MANAGER = params["manager"]
        MANAGER.app_log.warning("Init Hypernode Plugin")
    except:
        pass
    DESC = {"127.0.0.1": "localhost"}
    # Adjust paths from config
    global HNROUNDS_DIR
    HNROUNDS_DIR = os.path.join(MANAGER.config.get_live_path(), "hnrounds")
    print("HNROUNDS_DIR", HNROUNDS_DIR)
    global HNCOLORED
    HNCOLORED = os.path.join(MANAGER.config.get_live_path(), "colored.json")
    print("HNCOLORED", HNCOLORED)
    global LEDGER_PATH
    LEDGER_PATH = MANAGER.config.get_ledger_db_path()
    # os.path.join(MANAGER.base_folder, "static/ledger .db")
    print("LEDGER_PATH", LEDGER_PATH)
    global POWSTATUS_PATH
    POWSTATUS_PATH = os.path.join(MANAGER.config.get_live_path(), "powstatus.json")
    print("POWSTATUS_PATH", POWSTATUS_PATH)
    try:
        os.mkdir(HNROUNDS_DIR)
    except:
        pass
    # Init colored lists while we are in solo mode
    init_colored()
    # sys.exit()
    try:
        ip_cache_filename = MANAGER.config.get_file_path("live", "ipresolv.conf")
        with open(ip_cache_filename, "r") as f:
            DESC = json.load(f)
    except:
        pass
    if len(DESC) < 1:
        DESC = json.loads(CACHE)
    get_db()  # Init global DB
    # TODO: Since we create it at init, we could just use the LEDBER_DB global everywhere, without more checks.


def get_db():
    global LEDGER_DB
    if not LEDGER_DB:
        LEDGER_DB = sqlite3.connect(LEDGER_PATH, timeout=10, check_same_thread=False)
        # TODO: additional checks here for indices or pragmas
    return LEDGER_DB


def filter_colored(colored):
    for color in COLORS:
        colored[color] = COLORED[color]
    return colored


def action_fullblock(full_block):
    """
    Update colored list on new tw
    """
    global COLORED
    for tx in full_block["transactions"]:
        if tx[3] == POW_CONTROL_ADDRESS:
            # This is ours
            operation = str(tx[10])
            if operation.startswith("color:"):
                # and it's a color payload
                _, color = operation.split(":")
                items = tx[11].strip().split(",")
                COLORED[color] = items
                with open(HNCOLORED, "w") as f:
                    json.dump(COLORED, f)


def get_desc(ip):
    global DESC
    global UPDATED
    if ip in DESC:
        desc = DESC[ip]
    else:
        # filterwarnings(action="ignore")
        try:
            obj = IPWhois(ip)
            res = obj.lookup_whois()
            desc = res.get("asn_description")
        except:
            desc = ""
        # resetwarnings()
        if desc:
            UPDATED = True
            DESC[ip] = desc.lower()
    return desc


def filter_peer_ip(peer_ip):
    desc = get_desc(peer_ip["ip"])
    if desc:
        for cloud in COLORED["cloud"]:
            if cloud in desc and (peer_ip["ip"] not in COLORED["white"]):
                MANAGER.app_log.warning(
                    "Spam Filter: Blocked IP {}".format(peer_ip["ip"])
                )
                peer_ip["ip"] = "banned"
    return peer_ip


def filter_rollback_ip(peer_ip):
    if peer_ip["ip"] in COLORED["brown"]:
        MANAGER.app_log.warning(
            "Spam Filter: No rollback from {}".format(peer_ip["ip"])
        )
        peer_ip["ip"] = "no"
    return peer_ip


def check_local(socket_handler):
    remote_ip = socket_handler.getpeername()[0]
    # TODO: add extra ip from config, like our public ip (docker case)
    if remote_ip not in ["127.0.0.1"]:
        raise ValueError("ip {} not allowed for that command".format(remote_ip))


# TODO: add a decorator so that commands are only allowed from localhost, and are locked (one at a time)
def HN_test(socket_handler):
    """Merely test the db connection"""
    check_local(socket_handler)
    MANAGER.app_log.warning("Extra command HN_test")
    try:
        db = get_db()
        res = db.execute("PRAGMA table_info(transactions)")
        data = res.fetchall()
        MANAGER.execute_filter_hook(
            "send_data_back", {"socket": socket_handler, "data": data}, first_only=True
        )
    except Exception as e:
        MANAGER.app_log.warning("HN_test exception {}".format(e))


def HN_reg_check_weight(socket_handler, params):
    """Checks a weight at a given POW height"""
    check_local(socket_handler)
    MANAGER.app_log.warning(
        "Extra command HN_reg_check_weight {}".format(",".join(params))
    )
    try:
        db = get_db()
        data = LedgerQueries.reg_check_weight(db, params[0], int(params[1]))
    except Exception as e:
        MANAGER.app_log.warning("HN_reg_check_weight exception {}".format(e))
        data = -1
    MANAGER.execute_filter_hook(
        "send_data_back", {"socket": socket_handler, "data": data}, first_only=True
    )


def HN_quick_check_balance(socket_handler, params):
    """Checks a balance at a given POW height"""
    check_local(socket_handler)
    MANAGER.app_log.warning(
        "Extra command HN_quick_check_balance {}".format(",".join(params))
    )
    try:
        db = get_db()
        data = LedgerQueries.quick_check_balance(db, params[0], int(params[1]))
    except Exception as e:
        MANAGER.app_log.warning("HN_quick_check_balance exception {}".format(e))
        data = -1
    MANAGER.execute_filter_hook(
        "send_data_back", {"socket": socket_handler, "data": data}, first_only=True
    )


def HN_ts_of_block(socket_handler, params):
    """Returns TS of a given POW height"""
    check_local(socket_handler)
    MANAGER.app_log.warning("Extra command HN_ts_of_block {}".format(",".join(params)))
    try:
        db = get_db()
        data = LedgerQueries.get_ts_of_block(db, int(params[0]))
    except Exception as e:
        MANAGER.app_log.warning("HN_ts_of_block exception {}".format(e))
        data = -1
    MANAGER.execute_filter_hook(
        "send_data_back", {"socket": socket_handler, "data": data}, first_only=True
    )


def HN_block_before_ts(socket_handler, params):
    """Returns TS of a given POW height"""
    check_local(socket_handler)
    MANAGER.app_log.warning(
        "Extra command HN_block_before_ts {}".format(",".join(params))
    )
    try:
        db = get_db()
        data = LedgerQueries.get_block_before_ts(db, float(params[0]))
    except Exception as e:
        MANAGER.app_log.warning("HN_block_before_ts exception {}".format(e))
        data = -1
    MANAGER.execute_filter_hook(
        "send_data_back", {"socket": socket_handler, "data": data}, first_only=True
    )


def HN_last_block_ts(socket_handler):
    check_local(socket_handler)
    MANAGER.app_log.warning("Extra command HN_last_block_ts")
    try:
        data = LedgerQueries.get_last_block_ts(get_db())
        # print(">> data", data)
    except Exception as e:
        MANAGER.app_log.warning("HN_last_block_ts exception {}".format(e))
        data = -1
    MANAGER.execute_filter_hook(
        "send_data_back", {"socket": socket_handler, "data": data}, first_only=True
    )


def HN_plugin_version(socket_handler):
    """Sends back running versions of the plugin and query helper."""
    MANAGER.app_log.warning("Extra command HN_plugin_version")
    try:
        MANAGER.execute_filter_hook(
            "send_data_back",
            {
                "socket": socket_handler,
                "data": {
                    "hn_plugin": __version__,
                    "ledger_queries": ledger_queries_version,
                },
            },
            first_only=True,
        )
    except Exception as e:
        MANAGER.app_log.warning("HN_plugin_version exception {}".format(e))


def HN_reg_check_weights(socket_handler, params):
    """Check a list of addresses for weight, at a given timestamp"""
    check_local(socket_handler)
    # MANAGER.app_log.warning("Extra command HN_reg_check_weights {}".format(" ; ".join(params)))
    MANAGER.app_log.warning(
        "Extra command HN_reg_check_weights at ts {}".format(params[1])
    )
    try:
        db = get_db()
        addresses = params[0].split(",")
        result = {}
        timestamp = float(params[1])
        pow_height = LedgerQueries.get_block_before_ts(db, timestamp)
        for address in addresses:
            weight = LedgerQueries.reg_check_weight(db, address, pow_height)
            result[address] = weight
    except Exception as e:
        MANAGER.app_log.warning("HN_reg_check_weights exception {}".format(e))
        result = {}
    MANAGER.execute_filter_hook(
        "send_data_back", {"socket": socket_handler, "data": result}, first_only=True
    )


def reg_extract(openfield, address):
    """
    Extract data from openfield. 'ip:port:pos' or with option 'ip2:port:pos2,reward=bis2a'

    :param openfield: str
    :param address: str
    :return: tuple (ip, port, pos, reward)
    """
    options = {}
    if "," in openfield:
        # Only allow for 1 extra param at a time. No need for more now, but beware if we add!
        parts = openfield.split(",")
        openfield = parts.pop(0)
        for extra in parts:
            key, value = extra.split("=")
            options[key] = value
    ip, port, pos = openfield.split(":")
    reward = options["reward"] if "reward" in options else address
    source = options["source"] if "source" in options else None
    if source and source != address:
        raise ValueError("Bad source address")
    return ip, port, pos, reward


def extract_reason(openfield):
    """
    Extract optional reason data from openfield.

    :param openfield: str
    :return: str
    """
    if "," in openfield:
        # Only allow for 1 extra param at a time. No need for more now, but beware if we add!
        parts = openfield.split(",")
        parts.pop(0)
        for extra in parts:
            key, value = extra.split("=")
            if key == "reason":
                return value
    return ""


def validate_pow_address(address: str) -> Union[None, bool]:
    """
    Validate a bis (PoW address).

    :param address:
    :return: True if address is valid, raise a ValueError exception if not.
    """
    # TODO!: To evolve with more addresses
    # if re.match("[abcdef0123456789]{56}", address):
    if SignerFactory.address_is_valid(address):
        return True
    raise ValueError("Bis Address format error: {}".format(address))


def validate_pos_address(address, network=None):
    """
    Decode and verify the checksum of a Base58 encoded string.

    :param address: the address string to validate
    :param network: The network id to validate against
    :return: The 20 bytes hash of the pubkey if address matches format and network, or throw an exception
    """
    NETWORK_ID = b"\x19"
    if not re.match("[A-Za-z0-9]{34}", address):
        # B9oMPPW5hZEAAuq8oCpT6i6pavPJhgXViq
        raise ValueError("Invalid address format: {}".format(address))
    if not network:
        network = NETWORK_ID
    raw = base58.b58decode(address)
    result, check = raw[:-4], raw[-4:]
    digest = blake2b(result, digest_size=4).digest()
    if check != digest:
        raise ValueError("Invalid address checksum for {}".format(address))
    if result[0] != ord(network):
        raise ValueError(
            "Invalid Network: 0x{:02x} instead of 0x{:02x}".format(
                result[0], ord(network)
            )
        )
    return result[1:]


def path_for_round_cache(a_round: int) -> str:
    return path.join(HNROUNDS_DIR, "{}.json".format(a_round))


def get_regs_from(pos_round: int) -> tuple:
    all_cache = os.listdir(HNROUNDS_DIR)
    rounds = [int(file[:-5]) for file in all_cache]  # strip .json
    rounds = sorted(rounds, reverse=True)
    regs = {}
    checkpoint = 773800
    for a_round in rounds:
        if a_round <= pos_round:
            with open(path_for_round_cache(a_round)) as fp:
                info = json.load(fp)
                MANAGER.app_log.warning(
                    "Found cached round {} with ref_height ".format(
                        a_round, info["params"]["ref_height"]
                    )
                )
                return info["regs"], info["params"]["ref_height"]
    return regs, checkpoint


def HN_reg_round(socket_handler, params: list) -> None:
    # only allow for local host, will raise
    check_local(socket_handler)
    MANAGER.app_log.warning(
        "Extra command HN_reg_round {} {}".format(",".join(params), ROUND_LOCK.locked())
    )
    with ROUND_LOCK:
        try:
            pos_round, ref_timestamp, pow_height, ip = params[:4]
            ref_timestamp = float(ref_timestamp)
            pos_round = int(pos_round)
            pow_height = int(pow_height)
            if ip.lower() == "false":
                ip = False
            cache_file = path_for_round_cache(pos_round)
            if pow_height <= 0 and not ip:
                # Regular request, check if cached
                if os.path.isfile(cache_file):
                    with open(cache_file) as fp:
                        output = json.load(fp)
                    MANAGER.execute_filter_hook(
                        "send_data_back",
                        {"socket": socket_handler, "data": output},
                        first_only=True,
                    )
                    return
            height = pow_height
            if height <= 0:
                height = LedgerQueries.get_block_before_ts(get_db(), ref_timestamp)
            if height <= 0:
                MANAGER.execute_filter_hook(
                    "send_data_back",
                    {"socket": socket_handler, "data": False},
                    first_only=True,
                )
                return
            MANAGER.app_log.warning("Ref height={}".format(height))
            # Default start data if we have nothing
            output = {
                "params": {
                    "pos_round": pos_round,
                    "ref_timestamp": ref_timestamp,
                    "pow_height": pow_height,
                    "ref_height": height,
                }
            }
            regs = {}
            checkpoint = 773800  # No Hypernode tx earlier
            # list and get most recent cache before the one we want, get regs and checkpoint
            if not ip:
                regs, checkpoint = get_regs_from(pos_round - 1)
            MANAGER.app_log.warning(
                "Querying regs from {} to {}".format(checkpoint + 1, height)
            )
            #  print("c1", time())
            start = time()
            res = LedgerQueries.get_hn_regs_from_to(get_db(), checkpoint + 1, height)
            # print(">> RES ", res)
            if res is None:
                res = []
            delay = time() - start
            MANAGER.app_log.warning("HN_reg_round Query took {} sec".format(delay))
            # print(res)
            # process the regs
            show = False
            ip_feed = []
            for row in res:
                block_height, address, operation, openfield, timestamp = row
                valid = True
                show = False
                try:
                    if ip and "{}:".format(ip) in openfield:
                        show = True
                        ip_feed.append(
                            "Row {}: {}, {}, {}".format(
                                block_height, address, operation, openfield
                            )
                        )
                    hip, port, pos, reward = reg_extract(openfield, address)
                    if operation == "hypernode:register":
                        # There is a small hack here: the following tests seem to do nothing, but they DO
                        # raise an exception if there is a dup. Allow for single line faster test.
                        # since list comprehension is heavily optimized.
                        # invalid ip
                        ipaddress.ip_address(hip)
                        # invalid bis addresses
                        validate_pow_address(address)
                        validate_pow_address(reward)
                        # invalid pos address
                        validate_pos_address(pos)
                        # Dup ip?
                        [1 / 0 for items in regs.values() if items["ip"] == hip]
                        # Dup pos address?
                        [1 / 0 for items in regs.values() if items["pos"] == pos]
                        # Dup pow address?
                        if address in regs:
                            raise ValueError("Already an active registration")
                        # Requires a db query, runs last - Will raise if not enough.
                        # print("w1", time())
                        weight = LedgerQueries.reg_check_weight(
                            get_db(), address, block_height
                        )
                        # print("w2", time())
                        active = True  # by default
                        # inactive last round will no longer get a ticket.
                        # When computing reward, they will not be counted for the round.
                        # if config.COMPUTING_REWARD or a_round >= config.NEXT_HF_AT_ROUND:
                        regs[address] = dict(
                            zip(
                                [
                                    "ip",
                                    "port",
                                    "pos",
                                    "reward",
                                    "weight",
                                    "timestamp",
                                    "active",
                                ],
                                [
                                    str(hip),
                                    port,
                                    str(pos),
                                    str(reward),
                                    weight,
                                    timestamp,
                                    active,
                                ],
                            )
                        )
                        if show:
                            ip_feed.append("Ok, Weight={}".format(weight))
                    else:
                        # It's an unreg
                        if address in regs:
                            # unreg from owner
                            if (hip, port, pos) == (
                                regs[address]["ip"],
                                regs[address]["port"],
                                regs[address]["pos"],
                            ):
                                # same info
                                del regs[address]
                            else:
                                raise ValueError("Invalid unregistration params")

                        elif address == POW_CONTROL_ADDRESS:
                            regs = {
                                key: items
                                for key, items in regs.items()
                                if (items["ip"], items["port"], items["pos"])
                                != (hip, port, pos)
                            }
                            if show:
                                ip_feed.append(
                                    "Unreg by controller, reason '{}'.".format(
                                        extract_reason(openfield)
                                    )
                                )
                        else:
                            raise ValueError("Invalid un-registration sender")
                        if show:
                            ip_feed.append("Ok")

                except (ValueError, ZeroDivisionError) as e:
                    # print(e)
                    valid = False
                    if show:
                        ip_feed.append("Ko: {}".format(e))
                    pass
            output["ip_feed"] = ip_feed
            if regs:
                output["status"] = "{} PoW Valid HN.".format(len(regs))
            else:
                output["status"] = "No PoW Valid HN."
            output["regs"] = regs
            if int(pow_height) <= 0 and not ip:
                # Regular request, no ip feed, save cache
                del output["ip_feed"]
                with open(cache_file, "w") as fp:
                    json.dump(output, fp, indent=2)
            MANAGER.execute_filter_hook(
                "send_data_back",
                {"socket": socket_handler, "data": output},
                first_only=True,
            )
        except Exception as e:
            MANAGER.app_log.warning("HN_reg_round exception {}".format(e))
            MANAGER.execute_filter_hook(
                "send_data_back",
                {"socket": socket_handler, "data": False},
                first_only=True,
            )


def clean_hnround():
    path = HNROUNDS_DIR
    now = time()
    for f in os.listdir(path):
        full_file = os.path.join(path, f)
        if os.stat(full_file).st_mtime < now - 10 * 86400:
            if os.path.isfile(full_file) and ".json" in full_file:
                os.remove(full_file)


def test_colored():
    """Tries to load colored"""
    try:
        with open(HNCOLORED) as fp:
            test = json.load(fp)
    except Exception as e:
        MANAGER.app_log.error("colored.json {}".format(e))
        sleep(10)
        init_colored()


def action_status(status):
    global UPDATED
    if UPDATED:
        # save new descriptions on status
        ip_cache_filename = MANAGER.config.get_file_path("live", "ipresolv.conf")  # could be cached, by light use.
        with open(ip_cache_filename, "w") as f:
            json.dump(DESC, f)
        UPDATED = False
    # Update powstatus for the HN to read (could be moved to a HN_ Command)
    with open(POWSTATUS_PATH, "w") as f:
        json.dump(status, f)
    """
    # Not needed anymore since it lives in datadir, that can be mounted in docker.
    # not pretty. store in static also so it's a mount in docker context.    
    # TODO: needs to take real static path from config.
    with open("static/powstatus.json", "w") as f:
        json.dump(status, f)
    """
    # TODO: could be less frequent, like every hour only.
    clean_hnround()
    if not os.path.isfile(HNCOLORED):
        # Recreate colored if missing
        init_colored()
    test_colored()


def my_callback(command_name: str, socket_handler) -> None:
    """The magic is here. This is the generic callback handler answering to the extra command"""
    # This method could stay as this.
    if VERBOSE:
        MANAGER.app_log.warning("Got HN command {}".format(command_name[:50] + "..."))
    if command_name in globals():
        # this allow to transparently map commands to this module functions with no more code
        globals()[command_name](socket_handler)

    elif " " in command_name:
        # An alternate way is to define commands with inline param(s) and a custom separator (here, a space)
        command_name, *params = command_name.split(" ")
        if command_name in globals():
            globals()[command_name](socket_handler, params)
    else:
        MANAGER.app_log.warning("Undefined HN command {}".format(command_name))


def filter_extra_commands_prefixes(prefix_dict: dict) -> dict:
    """
    This is the initial - required - setup step.
    Easy peasy: just add our prefix(es) in the provided dict and send it back.
    """
    prefix_dict[PREFIX] = my_callback
    # More prefixes could go here
    return prefix_dict
