from decimal import Decimal
from libs import regnet
from math import ceil, log
from time import time as ttime
import sys, os
from libs.quantizer import quantize_two, quantize_ten
from libs.fork import Fork
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from libs.node import Node
    from libs.dbhandler import DbHandler

FORK = Fork()  # No need to instanciate one for every call to difficulty()

# See https://github.com/EggPool/bis-temp/blob/master/int/exp4.py

LOG_DIFF_STEPS = False  # For debug

DECIMAL1 = Decimal(1.0)
DECIMAL2 = Decimal(2.0)
DECIMAL16 = Decimal(16.0)
DECIMAL60 = Decimal(60.0)


def difficulty(node: "Node", db_handler: "DbHandler") -> tuple:
    ctime = ttime()  # So both methods use same time
    new = new_difficulty(node, db_handler, time=ctime)
    if True:  # Temp debug to make sure the "new" diff is exactly the same as the "old" one.
        diff = deprecated_difficulty(node, db_handler, time=ctime)
        if (new[0] != diff[0]) or (new[1] != diff[1]):
            print("new", new)
            print("deprec", diff)
            node.close("Diff check", force_exit=True)
            return diff
    return new
    """
    Arrgh
    new (103.937617136, 103.937617136, 5.829999923706055, 103.9367689274, 61.19997222208315, 3272417028612.557, 0.0008482086500018779, 1629302)
    deprec (103.9376171361, 103.9376171361, 5.829999923706055, 103.9367689274, 61.19997222208315, 3272417028612.562, 0.000848208650001907, 1629302)
    
    n timestamp_last 1585702107.8399999141693115234375
    n timestamp_before_last 1585702102.0099999904632568359375
    n timestamp_1441 1585613877.88000011444091796875
    n timestamp_1440 1585613979.88000011444091796875
    n block_time 61.19997222208314471774631076
    
    d timestamp_last 1585702107.8399999141693115234375
    d timestamp_before_last 1585702102.0099999904632568359375
    d timestamp_1441 1585613877.88000011444091796875
    d timestamp_1440 1585613979.88000011444091796875
    d block_time 61.19997222208314471774631076

    """
    """
    n timestamp_last 1586916198.28999996185302734375
    n timestamp_before_last 1586916182.440000057220458984375
    n timestamp_1441 1586830209.1600000858306884765625
    n timestamp_1440 1586830288.88000011444091796875
    n block_time 59.65931249989403618706597222
    
    d timestamp_last 1586916198.28999996185302734375
    d timestamp_before_last 1586916182.440000057220458984375
    d timestamp_1441 1586830209.1600000858306884765625
    d timestamp_1440 1586830288.88000011444091796875
    d block_time 59.65931249989403618706597222
    new (103.0069350375, 50.0, 15.849999904632568, 103.0062961875, 59.659312499894035, 2431596570425.9653, 0.0006388499499991907, 1649322)
    deprec (103.0069350374, 50.0, 15.849999904632568, 103.0062961875, 59.659312499894035, 2431596570425.9653, 0.0006388499499991907, 1649322)
    2020-04-15 09:14:36,108 close(191) Diff check

    """


def new_difficulty(node: "Node", db_handler: "DbHandler", time: float=0) -> tuple:
    """ EGG: Working on it, in testing"""
    try:
        ctime = ttime() if time == 0 else time
        last_block = db_handler.last_mining_transaction()
        timestamp_last, block_height = Decimal(last_block.timestamp), last_block.block_height
        # Beware, this is not thread safe! -
        node.last_block_timestamp = timestamp_last
        # node.last_block = block_height do not fetch this here, could interfere with block saving

        previous_block_ts = db_handler.last_block_timestamp(back=1)
        node.last_block_ago = int(ctime - int(timestamp_last))

        # Failsafe for regtest starting at block 1}
        timestamp_before_last = timestamp_last if previous_block_ts is None else Decimal(previous_block_ts)

        last1441 = db_handler.last_block_timestamp(back=1441 - 1)
        timestamp_1441 = Decimal(last1441) if last1441 else Decimal(0)  # Handle regnet case
        block_time_prev = (timestamp_before_last - timestamp_1441) / 1440
        temp = db_handler.last_block_timestamp(back=1440-1)
        timestamp_1440 = timestamp_1441 if temp is None else Decimal(temp)
        block_time = (timestamp_last - timestamp_1440) / 1440
        if LOG_DIFF_STEPS:
            print("n timestamp_last", timestamp_last)
            print("n timestamp_before_last", timestamp_before_last)
            print("n timestamp_1441", timestamp_1441)
            print("n timestamp_1440", timestamp_1440)
            print("n block_time", block_time)

        db_handler._execute(db_handler.c, "SELECT difficulty FROM misc ORDER BY block_height DESC LIMIT 1")
        diff_block_previous = Decimal(db_handler.c.fetchone()[0])

        time_to_generate = timestamp_last - timestamp_before_last

        if node.is_regnet:
            return (float('%.10f' % regnet.REGNET_DIFF), float('%.10f' % (regnet.REGNET_DIFF - 8)), float(time_to_generate),
                    float(regnet.REGNET_DIFF), float(block_time), float(0), float(0), block_height)

        hashrate = pow(2, diff_block_previous / DECIMAL2) / (block_time * ceil(28 - diff_block_previous / DECIMAL16))
        # Calculate new difficulty for desired blocktime of 60 seconds
        target = DECIMAL60
        # D0 = diff_block_previous
        difficulty_new = Decimal((2 / log(2)) * log(hashrate * target * ceil(28 - diff_block_previous / DECIMAL16)))
        # Feedback controller
        Kd = 10
        # print(type(difficulty_new), type(block_time), type(block_time_prev))
        difficulty_new = difficulty_new - Kd * (block_time - block_time_prev)
        diff_adjustment = (difficulty_new - diff_block_previous) / 720  # reduce by factor of 720

        if diff_adjustment > 1.0:
            diff_adjustment = DECIMAL1

        difficulty_new_adjusted = quantize_ten(diff_block_previous + diff_adjustment)
        # difficulty_new_adjusted = diff_block_previous + diff_adjustment
        difficulty2 = difficulty_new_adjusted
        if LOG_DIFF_STEPS:
            print("n difficulty_new", difficulty_new)
            print("n diff_adjustment", diff_adjustment)
            print("n difficulty2", difficulty2)

        # fork handling
        if node.is_mainnet:
            if block_height == FORK.POW_FORK - FORK.FORK_AHEAD:
                FORK.limit_version(node)
        # /fork handling

        diff_drop_time = 180

        if ctime > timestamp_last + 2 * diff_drop_time:
            # Emergency diff drop
            # Egg: kept the quantize2 to avoid side effects on specific values.
            # Should go away with a future fork.
            # time_difference = ctime - timestamp_last
            # diff_dropped = difficulty2 - 1 - 10 * (time_difference - 2 * diff_drop_time) / diff_drop_time
            time_difference = quantize_two(ctime) - quantize_two(timestamp_last)
            diff_dropped = quantize_ten(difficulty2) - quantize_ten(1) - quantize_ten(10 * (time_difference - 2 * diff_drop_time) / diff_drop_time)
        elif ctime > timestamp_last + diff_drop_time:
            # time_difference = ctime - timestamp_last
            # diff_dropped = difficulty2 + 1 - time_difference / diff_drop_time
            time_difference = quantize_two(ctime) - quantize_two(timestamp_last)
            diff_dropped = quantize_ten(difficulty2) + quantize_ten(1) - quantize_ten(time_difference / diff_drop_time)
        else:
            diff_dropped = difficulty2

        if difficulty2 < 50:
            difficulty2 = 50
        if diff_dropped < 50:
            diff_dropped = 50

        # Egg: kept the float('%.10f' % ...) to avoid side effects on specific values.
        # limiting to 2 or 3 decimals instead of 10 would likely be enough and avoid all decimals issues.
        return (float('%.10f' % difficulty2), float('%.10f' % diff_dropped), float(time_to_generate), float(diff_block_previous),
                float(block_time), float(hashrate), float(diff_adjustment), block_height)
        # need to keep float types here for database inserts support
    except Exception as e:
        # new chain or regnet
        # todo: stop if we are not in one of these 2 cases.
        print("New difficulty: {}".format(e))
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)

        difficulty2 = (24, 24, 0, 0, 0, 0, 0, 0)
        return difficulty2


def deprecated_difficulty(node, db_handler, time: float=0):
    try:
        ctime = ttime() if time == 0 else time

        db_handler._execute(db_handler.c, "SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 2")
        result = db_handler.c.fetchone()

        timestamp_last = Decimal(result[1])
        block_height = int(result[0])

        # Beware, this is not thread safe! -
        node.last_block_timestamp = timestamp_last
        # node.last_block = block_height do not fetch this here, could interfere with block saving

        previous = db_handler.c.fetchone()

        node.last_block_ago = int(ctime - int(timestamp_last))

        # Failsafe for regtest starting at block 1}
        timestamp_before_last = timestamp_last if previous is None else Decimal(previous[1])

        db_handler._execute_param(db_handler.c, (
            "SELECT timestamp FROM transactions WHERE block_height > ? AND reward != 0 ORDER BY block_height ASC LIMIT 2"),
                                  (block_height - 1441,))
        timestamp_1441 = Decimal(db_handler.c.fetchone()[0])
        block_time_prev = (timestamp_before_last - timestamp_1441) / 1440
        temp = db_handler.c.fetchone()
        timestamp_1440 = timestamp_1441 if temp is None else Decimal(temp[0])
        block_time = Decimal(timestamp_last - timestamp_1440) / 1440
        if LOG_DIFF_STEPS:
            print("d timestamp_last", timestamp_last)
            print("d timestamp_before_last", timestamp_before_last)
            print("d timestamp_1441", timestamp_1441)
            print("d timestamp_1440", timestamp_1440)
            print("d block_time", block_time)

        db_handler._execute(db_handler.c, "SELECT difficulty FROM misc ORDER BY block_height DESC LIMIT 1")
        diff_block_previous = Decimal(db_handler.c.fetchone()[0])

        time_to_generate = timestamp_last - timestamp_before_last

        if node.is_regnet:
            return (float('%.10f' % regnet.REGNET_DIFF), float('%.10f' % (regnet.REGNET_DIFF - 8)), float(time_to_generate),
                    float(regnet.REGNET_DIFF), float(block_time), float(0), float(0), block_height)

        hashrate = pow(2, diff_block_previous / Decimal(2.0)) / (
                block_time * ceil(28 - diff_block_previous / Decimal(16.0)))
        # Calculate new difficulty for desired blocktime of 60 seconds
        target = Decimal(60.00)
        # D0 = diff_block_previous
        difficulty_new = Decimal(
            (2 / log(2)) * log(hashrate * target * ceil(28 - diff_block_previous / Decimal(16.0))))
        # Feedback controller
        Kd = 10
        difficulty_new = difficulty_new - Kd * (block_time - block_time_prev)
        diff_adjustment = (difficulty_new - diff_block_previous) / 720  # reduce by factor of 720

        if diff_adjustment > Decimal(1.0):
            diff_adjustment = Decimal(1.0)

        difficulty_new_adjusted = quantize_ten(diff_block_previous + diff_adjustment)
        difficulty2 = difficulty_new_adjusted
        if LOG_DIFF_STEPS:
            print("d difficulty_new", difficulty_new)
            print("d diff_adjustment", diff_adjustment)
            print("d difficulty2", difficulty2)

        # fork handling
        if node.is_mainnet:
            if block_height == FORK.POW_FORK - FORK.FORK_AHEAD:
                FORK.limit_version(node)
        # /fork handling

        diff_drop_time = Decimal(180)

        if Decimal(ctime) > Decimal(timestamp_last) + Decimal(2 * diff_drop_time):
            # Emergency diff drop
            time_difference = quantize_two(ctime) - quantize_two(timestamp_last)
            diff_dropped = quantize_ten(difficulty2) - quantize_ten(1) \
                           - quantize_ten(10 * (time_difference - 2 * diff_drop_time) / diff_drop_time)
        elif Decimal(ctime) > Decimal(timestamp_last) + Decimal(diff_drop_time):
            time_difference = quantize_two(ctime) - quantize_two(timestamp_last)
            diff_dropped = quantize_ten(difficulty2) + quantize_ten(1) - quantize_ten(time_difference / diff_drop_time)
        else:
            diff_dropped = difficulty2

        if difficulty2 < 50:
            difficulty2 = 50
        if diff_dropped < 50:
            diff_dropped = 50

        return (
            float('%.10f' % difficulty2), float('%.10f' % diff_dropped), float(time_to_generate), float(diff_block_previous),
            float(block_time), float(hashrate), float(diff_adjustment),
            block_height)  # need to keep float here for database inserts support
    except:  # new chain or regnet
        difficulty2 = [24, 24, 0, 0, 0, 0, 0, 0]
        return difficulty2
