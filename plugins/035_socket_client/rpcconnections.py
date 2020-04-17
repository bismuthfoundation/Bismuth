"""
Bismuth default/legacy connection layer.
Json over sockets
This file is no more compatible with the Bismuth code, it's been converted to a class
EggPool 2018
"""

import json
import socket
import time
import threading

# Logical timeout
LTIMEOUT = 45
# Fixed header length
SLEN = 10


__version__ = '0.1.7'


class Connection(object):
    """Connection to a Bismuth Node. Handles auto reconnect when needed"""

    __slots__ = ('ipport', 'verbose', 'sdef', 'stats', 'last_activity', 'command_lock', 'raw')

    def __init__(self, ipport, verbose=False, raw=False):
        """ipport is an (ip, port) tuple"""
        self.ipport = ipport
        self.verbose = verbose
        self.raw = raw
        self.sdef = None
        self.last_activity = 0
        self.command_lock = threading.Lock()
        self.check_connection()

    def check_connection(self):
        """Check connection state and reconnect if needed."""
        if not self.sdef:
            try:
                if self.verbose:
                    print("Connecting to", self.ipport)
                self.sdef = socket.socket()
                self.sdef.connect(self.ipport)
                self.last_activity = time.time()
            except Exception as e:
                self.sdef = None
                raise RuntimeError("Connections: {}".format(e))

    def _send(self, data, slen=SLEN, retry=True):
        """Sends something to the server"""
        self.check_connection()
        try:
            self.sdef.settimeout(LTIMEOUT)
            # Make sure the packet is sent in one call
            sdata = str(json.dumps(data))
            res = self.sdef.sendall(str(len(sdata)).encode("utf-8").zfill(slen)+sdata.encode("utf-8"))
            if self.raw:
                print("sending raw:")
                print(str(len(sdata)).encode("utf-8").zfill(slen)+sdata.encode("utf-8"))
            self.last_activity = time.time()
            # res is always 0 on linux
            if self.verbose:
                print("send ", data)
            return True
        except Exception as e:
            # send failed, try to reconnect
            # TODO: handle tries #
            self.sdef = None
            if retry:
                if self.verbose:
                    print("Send failed ({}), trying to reconnect".format(e))
                self.check_connection()
            else:
                if self.verbose:
                    print("Send failed ({}), not retrying.".format(e))
                return False
            try:
                self.sdef.settimeout(LTIMEOUT)
                # Make sure the packet is sent in one call
                self.sdef.sendall(str(len(str(json.dumps(data)))).encode("utf-8").zfill(slen)+str(json.dumps(data)).encode("utf-8"))
                return True
            except Exception as e:
                self.sdef = None
                raise RuntimeError("Connections: {}".format(e))

    def _receive(self, slen=SLEN):
        """Wait for an answer, for LTIMEOUT sec."""
        self.check_connection()
        self.sdef.settimeout(LTIMEOUT)
        if self.raw:
            print("getting raw:")
        try:
            data = self.sdef.recv(slen)
            if self.raw:
                raw = data
            if not data:
                raise RuntimeError("Socket EOF")
            data = int(data)  # receive length
        except socket.timeout as e:
            self.sdef = None
            return ""
        try:
            chunks = []
            bytes_recd = 0
            while bytes_recd < data:
                chunk = self.sdef.recv(min(data - bytes_recd, 2048))
                if not chunk:
                    raise RuntimeError("Socket EOF2")
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)
            self.last_activity = time.time()
            if self.raw:
                print(raw + b''.join(chunks))
            segments = b''.join(chunks).decode("utf-8")
            return json.loads(segments)
        except Exception as e:
            """
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            """
            self.sdef = None
            raise RuntimeError("Connections: {}".format(e))

    def command(self, command, options=None):
        """
        Sends a command and return it's raw result.
        options has to be a list.
        Each item of options will be sent separately. So If you want to send a list, pass a list of list.
        """
        with self.command_lock:
            try:
                self._send(command)
                if options:
                    for option in options:
                        self._send(option, retry=False)
                ret = self._receive()
                return ret
            except Exception as e:
                """
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                """
                # TODO : better handling of tries and delay between
                if self.verbose:
                    print("Error <{}> sending command, trying to reconnect.".format(e))
                self.check_connection()
                self._send(command)
                if options:
                    for option in options:
                        self._send(option, retry=False)
                ret = self._receive()
                return ret

    def close(self):
        """Close the socket"""
        try:
            self.sdef.close()
        except Exception as e:
            pass


if __name__ == "__main__":
    print("I'm a module, can't run!")
