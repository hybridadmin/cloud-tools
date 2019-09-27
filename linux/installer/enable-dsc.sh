#!/bin/bash

if iptables -L INPUT | grep -P "5985|5986" >/dev/null 2>&1; then
	write-log "green" ">>> WSMAN rules already open in firewall <<<"
else
	write-log "bright_blue" ">>> Applying WSMAN firewall rules <<<"
	if [ $DISTRO == 'centos' ] && [ $RELEASE -ge '7' ]; then
		for i in  "${ALLOWED_SOURCES[@]}"; do
			sudo bash -c "firewall-offline-cmd --zone=public --add-rich-rule='rule family=ipv4 source address="$i" port port="5985-5986" protocol=tcp accept'"
		done
	else
		for i in "${ALLOWED_SOURCES[@]}"; do
			iptables -A INPUT -s $i -p tcp -m multiport --dports 5985:5986 -m state --state NEW -j ACCEPT
		done
	fi
fi

if [[ -r /etc/redhat-release ]]; then
	PKG_INSTALLER=$(which yum)
	OSSL_VER=$( openssl version | cut -d ' ' -f 2 | sed 's/.$//' | tr -d '.')
	cd /tmp	&& sudo $PKG_INSTALLER install -y -q python openssl unzip

	OMI_VERSION=$($PKG_INSTALLER list installed | grep -P "(^|\s)\omi.x86_64(?=\s|$)" | awk '{print $2}' | tr -d '[[:space:]]')
	if [[ $OMI_VERSION == *"1.1.0"* ]]; then
		write-log "bright_cyan" ">>> OMI package already installed ($OMI_VERSION) <<<"
	else
		write-log "bright_blue" ">>> OMI package not found. Installing <<<"
		OMI_LATEST=$(curl -s https://github.com/Microsoft/omi/releases  | grep "omi-.*_${OSSL_VER}.*.x64.rpm" | head -n 1 | cut -d '"' -f 2)
		rpm -Uvh "https://github.com/${OMI_LATEST}"
		sed -i -e 's/httpport=0/httpport=0,5985/g' /etc/opt/omi/conf/omiserver.conf
		finishconfig="true"
	fi

	DSC_VERSION=$($PKG_INSTALLER list installed | grep -P "dsc.x86_64" | awk '{print $2}' | tr -d '[[:space:]]')
	if [[ $DSC_VERSION == *"1.1.1"* ]]; then
		write-log "bright_cyan" ">>> DSC for linux package already installed ($DSC_VERSION) <<<"
	else
		write-log "bright_blue" ">>> DSC for linux package not found. Installing <<<"
		DSC_LATEST=$(curl -s https://github.com/Microsoft/PowerShell-DSC-for-Linux/releases  | grep "dsc-.*ssl_100.*.x64.rpm" | head -n 1 | cut -d '"' -f 2)
		rpm -Uvh "https://github.com/${DSC_LATEST}"
	fi

	if [[ $finishconfig == "true" ]]; then
		if [ $RELEASE == '6' ]; then
			chkconfig omid on && service omid restart
		else
			systemctl enable omid.service && systemctl restart  omid.service
		fi
	fi
else
### ubuntu			
	# https://gist.github.com/lukechilds/a83e1d7127b78fef38c2914c4ececc3c
	PKG_INSTALLER=$(which apt)
	OSSL_VER=$( openssl version | cut -d ' ' -f 2 | sed 's/.$//' | tr -d '.')
	cd /tmp && 	sudo $PKG_INSTALLER install -qqy python openssl unzip 

	if ! dpkg -l | grep omi | awk '{print $3}' | tr -d '[[:space:]]' >/dev/null 2>&1; then
		write-log "green" ">>> OMI package already installed <<<"
	else
		write-log "bright_blue" ">>> OMI package not found. Installing <<<"
		OMI_LATEST=$(curl -s https://github.com/Microsoft/omi/releases  | grep "omi-.*_${OSSL_VER}.*.x64.deb" | head -n 1 | cut -d '"' -f 2)
		wget "https://github.com/${OMI_LATEST}"
		sudo dpkg -i "/tmp/$(echo $OMI_LATEST | cut -d '/' -f 7)"
	fi

	if ! dpkg -l | grep dsc | awk '{print $3}' | tr -d '[[:space:]]' >/dev/null 2>&1; then
		write-log "green" ">>> DSC for linux package already installed <<<"
	else
		write-log "bright_blue" ">>> DSC for linux package not found. Installing <<<"
		DSC_LATEST=$(curl -s https://github.com/Microsoft/PowerShell-DSC-for-Linux/releases  | grep "dsc-.*ssl_100.*.x64.deb" | head -n 1 | cut -d '"' -f 2)
		wget "https://github.com/${DSC_LATEST}"
		sudo dpkg -i "/tmp/$(echo $DSC_LATEST | cut -d '/' -f 7)"
		sed -i -e 's/httpport=0/httpport=0,5985/g' /etc/opt/omi/conf/omiserver.conf
		service omid restart
	fi
fi
