# Scaffold for data dir reorg

Node is now to be run with a single command line param, the datadir.  
If nothing is given, it assumes ./datadir

wallet, config as well as chains are taken from the subdirs of datadir.

So, you can have a single codebase and run it from different contexts/stats just by specifying the right datadir.


Current state:

- datadir command line param
- wallet.der read from datadir
- config.txt / config_custom.txt read from datadir/config
- mandatory_message.json read from datadir/config
- peers.txt and suggested_peers.txt in datadir/live
- sequencing_last, index.db, ledger and hyper now live in datadir/chain-legacy
(have to be moved or copied from previous location to there)
- config takes care of adjusting paths and filenames for test and reg modes

- new "label" config param to give a name to the config set.
- prints label and paths at start, then waits 10 sec

- heavy3a.bin default location is now datadir.  
config file can optionally specify anotehr path. With no path, datadir/ is assumed. 
- ipresolv.json (500_hypernode) from datadir/live

# More

See readme from subdirs.


Q: Should wallet.der be stored there? Would make sense, but yet another location for other legacy tools to be aware of?

- heavy3a.bin  
neither live nor config item, can be here.
