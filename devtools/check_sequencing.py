# Independant chain sequencing test - for debug
# Dup code from node.

import sqlite3
import sys
# Specific path, non standard.
chain = "../../Bismuth-temp/static/ledger.db"

try:
    with open("../sequencing_last", 'r') as filename:
        sequencing_last = int(filename.read())
    print("Sequencing from", sequencing_last)
except:
    print("Sequencing anchor not found, going through the whole chain")
    sequencing_last = 0

conn = sqlite3.connect(chain)
c = conn.cursor()

# perform test on transaction table
y = None
for row in c.execute(
        "SELECT block_height FROM transactions WHERE reward != 0 AND block_height >= ? ORDER BY block_height ASC",
        (sequencing_last,)):
    y_init = row[0]
    if y is None:
        y = y_init
    if row[0] != y:
        print(f"Status: Chain {chain} transaction sequencing error at: {row[0]}. {row[0]} instead of {y}")
        sys.exit()
    y += 1

"""
https://stackoverflow.com/questions/802802/checking-sequence-with-sql-query

try 

select tx.block_height
from transactions tx
left join transactions prev 
    on tx.block_height = prev.block_height + 1
where tx.block_height >= 1592110 and tx.reward > 0 and prev.reward > 0
and prev.block_height is null

Will show gaps, not dups.
"""
