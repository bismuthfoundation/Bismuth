# Config dir

- mandatory_message.json  
Specific exchanges addresses requiring a message. Shipped with distro.

- config.txt  
Shipped with distro

- config_custom.txt  
User overrides.


node.py is to be run with an optional dir as first and only parameter.  
This parameter is the datadir directory to use.

No dir will use default ./datadir location, with legacy db
"regnet" as dir will use ./datadir location, with regnet mode.
"regnet2" as dir will use ./datadir location, with regnet V2 mode.
"V2" as dir will use ./datadir location, with V2 db mode.

Future versions will auto detect and convert to use V2 db unless told otherwise.
