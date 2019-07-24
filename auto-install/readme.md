# Auto install script

**This is an auto install for NODE alone**  
To be used by devs, exchanges, service providers.  
If you want to host a Hypernode, please use the 2 in 1 auto installer at https://github.com/bismuthfoundation/hypernode/tree/master/auto-install

- Tested on Ubuntu 18 Only
- Needs login as root
- will reboot the vps after install

- Experimental, use at your own risks, may break your vps and need os reinstall
- Does **not** set up the UFW firewall, to avoid conflicts with ssh port or other apps. see firewall sectino of the sccript if needed.

- Works well for me :) 

A Docker images is now also available:  
https://github.com/bismuthfoundation/Bismuth-Docker/tree/master/node
