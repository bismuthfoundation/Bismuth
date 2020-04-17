"""
Plugin

Native Bismuth Socket client

Uses the clean object lib from BismuthAPI

Provides helper filters actions for other plugins
"""

import json
from bismuthcore.rpcconnection import RpcConnection
import socket

__version__ = '0.0.3'


MANAGER = None

VERBOSE = True


def action_init(params):
    global MANAGER
    try:
        MANAGER = params['manager']
        MANAGER.app_log.warning("Init Native Socket client Plugin")
    except:
        # Better ask forgiveness than permission
        pass


def filter_native_command(command_dict):
    """
    Gets a command, calls it, and affect result.
    """
    # Set defaults if needed
    if not command_dict.get('host', False):
        command_dict['host'] = '127.0.0.1'
    if not command_dict.get('port', False):
        command_dict['port'] = 5658
    if not command_dict.get('params', False):
        command_dict['params'] = None
    try:
        connection = RpcConnection((command_dict['host'], command_dict['port']), verbose=VERBOSE)
        result = connection.command(command_dict['command'], command_dict['params'])
        command_dict['result'] = result
    except Exception as e:
        MANAGER.app_log.warning("native_command error {}".format(e))
        command_dict['result'] = "Error"
        command_dict['error'] = str(e)
    return command_dict


def filter_receive_extra_packet(packet_dict):
    """Wait for a legacy packet and fills in "data" with the data"""
    sdef = packet_dict['socket']
    try:
        data = sdef.recv(10)
        if not data:
            raise RuntimeError("Socket EOF")
        data = int(data)  # receive length
    except socket.timeout as e:
        MANAGER.app_log.warning("Socket error {}".format(e))
        return ""
    try:
        chunks = []
        bytes_recd = 0
        while bytes_recd < data:
            chunk = sdef.recv(min(data - bytes_recd, 2048))
            if not chunk:
                raise RuntimeError("Socket EOF2")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        segments = b''.join(chunks).decode("utf-8")
        packet_dict['data'] = json.loads(segments)
        return packet_dict

    except Exception as e:
        raise RuntimeError("_receive: {}".format(e))


def filter_send_data_back(packet_dict):
    """Sends the data back to the given socket"""
    sdata = str(json.dumps(packet_dict['data']))
    res = packet_dict['socket'].sendall(str(len(sdata)).encode("utf-8").zfill(10) + sdata.encode("utf-8"))
    # res is always 0 on linux
    packet_dict['result'] = True
    return packet_dict
