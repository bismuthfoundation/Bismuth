"""
Helper for log config
Kept from legacy code
"""

import logging, sys
from logging.handlers import RotatingFileHandler


def filter_status(record):
    """"
    Only displays log messages about status info
    or ERROR level
    """
    if ("Status:" in str(record.msg)) or (record.levelname == 'ERROR'):
        return 1
    else:
        return 0


def log(log_file, level_input="WARNING", terminal_output=False):
    level = logging.WARNING
    if level_input == "DEBUG":
        level = logging.DEBUG
    if level_input == "INFO":
        level = logging.INFO
    if level_input == "WARNING":
        level = logging.WARNING
    if level_input == "ERROR":
        level = logging.ERROR
    if level_input == "CRITICAL":
        level = logging.CRITICAL

    log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
    my_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5 * 1024 * 1024,
                                     backupCount=2, encoding="utf-8", delay=0)
    my_handler.setFormatter(log_formatter)
    my_handler.setLevel(level)
    app_log = logging.getLogger('root')
    app_log.setLevel(level)
    app_log.addHandler(my_handler)

    # Handled by tornado default colored handler
    """
    # This part is what goes on console.
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    # TODO: We could have 2 level in the config, one for screen and one for files.
    print("Logging level: {} ({})".format(level_input, level))
    if not terminal_output:
        ch.addFilter(filter_status)
        # No need for complete func and line info here.
        formatter = logging.Formatter('%(asctime)s %(message)s')
    else:
        formatter = logging.Formatter('%(asctime)s %(funcName)s(%(lineno)d) %(message)s')
    ch.setFormatter(formatter)
    app_log.addHandler(ch)
    """
    return app_log


def status_log(log_file, level_input="INFO", terminal_output=False):
    level = logging.INFO
    if level_input == "DEBUG":
        level = logging.DEBUG
    if level_input == "INFO":
        level = logging.INFO
    if level_input == "WARNING":
        level = logging.WARNING
    if level_input == "ERROR":
        level = logging.ERROR
    if level_input == "CRITICAL":
        level = logging.CRITICAL

    log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
    my_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5 * 1024 * 1024,
                                     backupCount=2, encoding="utf-8", delay=0)
    my_handler.setFormatter(log_formatter)
    my_handler.setLevel(level)
    status_log = logging.getLogger('status')
    status_log.setLevel(level)
    status_log.addHandler(my_handler)


    return status_log
