# TODO: EGG: I'd say this can disappear unless code from ../log.py gets migrated in there
# Only one can remain from logger.py and log.py

from logging import Logger

"""
class MyLogger:
    def __init__(self, app_log: Logger):
        self._app_log = app_log

    def warning(self, message: str='', category: str='N/A'):
        # print(f"warning cat {category}")
        self._app_log.warning(message)

    def info(self, message: str='', category: str='N/A'):
        # print(f"info cat {category}")
        self._app_log.info(message)

    def error(self, message: str='', category: str='N/A'):
        # print(f"error cat {category}")
        self._app_log.error(message)

    def debug(self, message: str='', category: str='N/A'):
        # print(f"debug cat {category}")
        self._app_log.debug(message)
"""


class Logger():
    def __init__(self):
        # self._app_log = None
        self.app_log = None
        self.mempool_log = None
        self.peers_log = None
        self.consensus_log = None
        self.dev_log = None

    def set_app_log(self, app_log: Logger, mempool_log: Logger=None, peers_log: Logger=None, consensus_log: Logger=None, dev_log: Logger=None):
        self.app_log = app_log
        self.mempool_log = mempool_log if mempool_log is not None else app_log
        self.peers_log = peers_log if peers_log is not None else app_log
        self.consensus_log = consensus_log if consensus_log is not None else app_log
        self.dev_log = dev_log if dev_log is not None else app_log
        # self.app_log = MyLogger(app_log)



