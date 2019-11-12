#!/bin/bash
# 2019 - Bismuth Foundation
# Distributed under the MIT software license, see http://www.opensource.org/licenses/mit-license.php.

# Usage: bash ./bis-node-alone-install.sh
# or one liner : curl https://raw.githubusercontent.com/bismuthfoundation/Bismuth/master/auto-install/bis-node-alone-install.sh|bash
# Setup a regular Bismuth node alone on a fresh Ubuntu 18 install.

# BEWARE: check configure_firewall to activate.

VERSION="0.1.2"

create_swap() {
	if [ -d /swapfile ]; then
		echo "Swap file already there"
	else
		fallocate -l 3G /swapfile
		chmod 600 /swapfile
		mkswap /swapfile
		swapon /swapfile
		echo "/swapfile   none    swap    sw    0   0" >> /etc/fstab
		echo "Swap file activated"
	fi
}

config_os() {
	if ! cat /etc/security/limits.conf | grep "root soft nofile 65535"; then
        echo "root soft nofile 65535" >> /etc/security/limits.conf
        echo "root hard nofile 65535" >> /etc/security/limits.conf
	fi
	if ! cat /etc/sysctl.conf | grep "fs.file-max = 100000"; then
	    echo "fs.file-max = 100000" >> /etc/sysctl.conf
	fi
	if ! cat /etc/sysctl.conf | grep "vm.swappiness = 10"; then
	    echo "vm.swappiness = 10" >> /etc/sysctl.conf
	fi
	if ! cat /etc/sysctl.conf | grep "vm.vfs_cache_pressure = 50"; then
	    echo "vm.vfs_cache_pressure = 50" >> /etc/sysctl.conf
        fi
        sysctl -p
	echo 1 > /proc/sys/net/ipv4/tcp_low_latency
}


update_repos() {
	echo "Updating repos..."
    DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" update
    DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
}


install_dependencies() {
	echo "Installing apt dependencies"
	# apt update -y
	# This may be enough,
    # apt install ufw unzip ntpdate python3-pip sqlite3 -y
    apt install ufw unzip ntpdate python3-pip sqlite3 build-essential python3-dev -y
	# ntpdate ntp.ubuntu.com
	# apt install ntp -y
}


configure_firewall() {
	echo "*NOT* Configuring Firewall"
    #ufw disable
    #ufw allow ssh/tcp
    #ufw limit ssh/tcp
    # node port
    #ufw allow 5658/tcp
    # HN port
    #ufw allow 6969/tcp
    # Wallet server
    #ufw allow 8150/tcp
    # Websocket server
    #ufw allow 8155/tcp
    #ufw logging on
    #ufw default deny incoming
    #ufw default allow outgoing
    #ufw --force enable
}


download_node() {
	echo "Fetching Node"
	cd
    if [ -f ./master.zip ]; then
        rm master.zip
	fi
    wget https://github.com/bismuthfoundation/Bismuth/archive/master.zip
    unzip master.zip
    mv Bismuth-master Bismuth
    cd Bismuth
    echo "Configuring node"
    echo "ram=False" >> config_custom.txt
    echo "full_ledger=True" >> config_custom.txt
    echo "mempool_ram=False" >> config_custom.txt
    echo "Downloading bootstrap"
    cd static
    if [ -f ./ledger-verified.tar.gz ]; then
        rm ledger-verified.tar.gz
	fi
    wget https://snapshots.s3.nl-ams.scw.cloud/ledger-verified.tar.gz
    tar -zxf ledger-verified.tar.gz
    # Make some room
    rm ledger-verified.tar.gz
    echo "Getting node sentinel"
    cd /root/Bismuth
    wget https://gist.githubusercontent.com/EggPool/e7ad9baa2b32e4d7d3ba658a40b6d643/raw/934598c7ff815180b913d6549bd2d9688e016855/node_sentinel.py
    echo "Installing PIP requirements"
    pip3 install setuptools ipwhois
    pip3 install -r requirements-node.txt
}

install_plugin() {
	echo "Installing companion plugin"
	mkdir /root/Bismuth/plugins
	mkdir /root/Bismuth/plugins/500_hypernode
  cd /root/Bismuth/plugins/500_hypernode
	wget https://raw.githubusercontent.com/bismuthfoundation/hypernode/master/node_plugin/__init__.py
}

start_node() {
	echo "Starting node"
	cd
	screen -d -S node -m bash -c "cd Bismuth;python3 node.py" -X quit
}

wait_ledger() {
	echo "Waiting for ledger to download and extract"
	while true; do
	 if [ ! -f /root/Bismuth/static/ledger.db ]; then
		echo "."
		sleep 10
	 else
	   break
	 fi
	done
}


add_cron_jobs() {
	# Node sentinel
  echo "Inserting example node sentinel cronjob, but not activated"
	if ! crontab -l | grep "node_sentinel"; then
	  (crontab -l ; echo "#* * * * * cd /root/Bismuth;python3 node_sentinel.py") | crontab -
	fi
}

if [ "$(whoami)" != "root" ]; then
  echo "Script must be run as root"
  exit -1
fi

while true; do
 if [ -d /root/Bismuth ]; then
   printf "/root/Bismuth/ already exists! The installer will delete this folder. Continue anyway?(Y/n)"
   pID=$(ps -ef | grep node.py | awk '{print $2}' | head -n 1)
   kill ${pID}
   rm -rf /root/Bismuth/
   break
 else
   break
 fi
done

cd
create_swap
config_os
update_repos
install_dependencies
configure_firewall
download_node
install_plugin

# cron_jobs are what will launch at boot and auto-restart node - not acctivated by default.
add_cron_jobs


echo "Rebooting server."
reboot
