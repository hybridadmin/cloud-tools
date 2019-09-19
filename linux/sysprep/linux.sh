#!/bin/bash

# Disk partitions
# 512 /boot
# 256 EFI ESP
# Rest = /
# VG = ubuntu-vg / LV = root
# New-VHD -Path "E:\Hyper-V\TEST992\VPS_Ubuntu_16.04_x64_Gen2.vhdx" -SizeBytes 10GB -Dynamic -BlockSizeBytes 1MB

## Fix for Centos 7/8 - [[ $RELEASE =~ ^[7-8]{1}$ ]]
CURRENT_SCRIPT="$0"

##variables
COUNTRY_CODE=$(curl -s "http://api.ipapi.com/check?access_key=d6c224f073f8cbe9de4c14999f39a93c&fields=country_code" | cut -d ':' -f2 | cut -d '"' -f2)
ADD_POWERSHELL_DSC="false"
HOLD_KERNEL_UPDATES="false"
PREP_FOR_AZURE="false"
BLACKLIST_MODULES="false"
CLOUD_PART_TOOLS="false"
ALLOWED_SOURCES=("196.220.32.0/24" "41.185.11.0/24")

## Color logger
if [ ! -f /tmp/color_logger.sh ]; then
	curl -s -o /tmp/color_logger.sh https://raw.githubusercontent.com/hybridadmin/color-logger/master/lib/color_logger.sh
fi
echo "Enabling colored output"
. /tmp/color_logger.sh
## Color logger

function configure_ntp (){
	NTP_CONFIG=$1
	DISTRO=$2
	
	if [ $DISTRO == "centos" ]; then NTP_SERVICE="ntpd"; else NTP_SERVICE="ntp"; fi
	
	cp ${NTP_CONFIG} "${NTP_CONFIG}.orig"
	sed -i "s/0.${DISTRO}.pool.ntp.org/za.pool.ntp.org/g" ${NTP_CONFIG}
    sed -i "/[0-9].${DISTRO}.pool.ntp.org/d" ${NTP_CONFIG}
	
	systemctl enable chronyd && systemctl restart chronyd
	chronyc sources
}

function harden_ssh(){
    # https://www.sshaudit.com/hardening_guides.html
    KEXALGS="curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256"
    MACS="hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
    CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    
    sed -i -e "s/KexAlgorithms.*/KexAlgorithms ${KEXALGS}/g" /etc/ssh/sshd_config
    sed -i -e "s/MACs.*/MACs ${MACS}/g" /etc/ssh/sshd_config
    sed -i -e "s/Ciphers.*/${CIPHERS}/g" /etc/ssh/sshd_config
    sed -i -e "s/AuthorizedKeysFile.*/AuthorizedKeysFile .ssh/authorized_keys/g" /etc/ssh/sshd_config
    sed -i 's/#\(.*ssh_host.*\(rsa\|ed25519\).*\)/\1/' /etc/ssh/sshd_config
    sed -i '/#\(.*ssh_host.*\(dsa\).*\)/d' /etc/ssh/sshd_config
    
    rm /etc/ssh/ssh_host_*key*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key < /dev/null
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key < /dev/null
   
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
}

### Start Distro Detection ###
if [[ `which yum` ]]; then
	DISTRO=$(cat /etc/*release | grep -E "^(Cent|Fedo|Redh)" | awk '{print $1}' | head -n1 | tr '[A-Z]' '[a-z]')
	PKG_INSTALLER=$(which yum)
	MAINLINE_KERNEL="false"
	EPEL_REPO="true"
	REMI_REPO="true"
	OPENLOGIC_REPO="false"
	REQUIRED_PKGS="grubby nano partx gdisk parted wget python-pyasn1 net-tools python python-devel pam-devel openssl-devel policycoreutils-python yum-utils yum-cron"
elif [[ `which apt` ]]; then
	DISTRO=$(lsb_release -is | tr '[A-Z]' '[a-z]')
	PKG_INSTALLER=$(which apt)
	export DEBIAN_FRONTEND=noninteractive
	UPDATE_MIRROR_LIST="false"
	OPENLOGIC_REPO="false"
	ENHANCED_SESSION_MODE="false"
	REQUIRED_PKGS="gdisk parted wget aptitude git debconf-utils pwgen"
else
   echo "OS NOT DETECTED"
fi
### End Distro Detection ###

write-log "bright_cyan" ">>> BEGINNING SYSPREP <<<"
#https://unix.stackexchange.com/questions/138744/inserting-a-line-in-a-file-only-if-this-line-isnt-yet-part-the-file
#https://gist.github.com/jakelee8/d11248bcae380aeea630a890713ec16b
if [[ $(swapon -s | tail -n1 | awk '{print $2}') == "partition" ]]; then 	
	write-log "green" ">>> SWAP Partition found... Skipping <<<"
else 	
	if [ ! -f /mnt/swapfile-1 ]; then 
		write-log "bright_yellow" ">>> Creating SWAP file <<<"
		fallocate -l 1G /mnt/swapfile-1
		chmod 600 /mnt/swapfile-1 && mkswap /mnt/swapfile-1 && swapon /mnt/swapfile-1
		sudo bash -c "echo '/mnt/swapfile-1 swap swap defaults 0 0'" >> /etc/fstab
	fi 
	
	if grep -q -E '^vm.swappiness=10$' /etc/sysctl.conf; then
		write-log "green" ">>> Swappiness setting: 10, Skipping <<<";
	else
		write-log "bright_blue" ">>> Setting Swappiness value to 10 <<<";
		sed -i -e 's/.*vm.swappiness=.*/vm.swappiness=10/g' /etc/sysctl.conf 
	fi
	#sysctl -p	
fi

if [ $DISTRO == 'centos' ] || [ $DISTRO == 'redhat' ]; then
    # https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-upload-centos
    
	RELEASE=$(sed 's/Linux//g' < /etc/redhat-release | awk '{print $3}' | tr -d " " | cut -c-1)	
	MINOR_VERSION=$(sed 's/Linux//g' < /etc/redhat-release | awk '{print $3}' | tr -d " " | cut -d "." -f 2)
	
	write-log "bright_blue" ">>> DETECTED DISTRO: $DISTRO - RELEASE: ${RELEASE} <<<"

    if [[ $RELEASE == '7' ]]; then 
        sudo $PKG_INSTALLER groups mark convert
    fi 

	write-log "bright_yellow" ">>> Updating system <<<"
	$PKG_INSTALLER clean metadata
	sudo $PKG_INSTALLER makecache
	
	if [ `$PKG_INSTALLER updateinfo list available | wc -l` -gt 0 ]; then 
		sudo $PKG_INSTALLER -y -q update
	fi
	
	if $PKG_INSTALLER list installed | grep -P "(alsa-*|ivtv-*|iwl*firmware|aic94xx-firmware)" >/dev/null 2>&1; then
		write-log "green" ">>> No Unrequired packages to remove from system <<<"
	else
		write-log "bright_yellow" ">>> Removing Unrequired packages from system <<<"
		sudo $PKG_INSTALLER -y -q remove alsa-* ivtv-* iwl*firmware aic94xx-firmware	
	fi
	
	if [[ $EPEL_REPO == "true" ]]; then 
		if $PKG_INSTALLER list installed | grep -P "epel-release" >/dev/null 2>&1; then
			write-log "green" ">>> EPEL repo already enabled. <<<"
		else
			write-log "bright_blue" ">>> Installing EPEL repo package <<<"
			sudo $PKG_INSTALLER install -y -q epel-release
		fi
	fi 	

	if [[ $REMI_REPO == "true" ]]; then 	
		if $PKG_INSTALLER list installed | grep -P "remi-release" >/dev/null 2>&1; then
			write-log "green" ">>> REMI repo already enabled. <<<"
		else
			write-log "bright_blue" ">>> Installing REMI repo package <<<"
			rpm -Uvh "http://rpms.famillecollet.com/enterprise/remi-release-${RELEASE}.rpm"
		fi
	fi 
		
	if [ ! -z "$REQUIRED_PKGS" ]; then 
		write-log "bright_yellow" ">>> Installing required packages [$REQUIRED_PKGS] <<<"
		echo $REQUIRED_PKGS | xargs -P1 sudo $PKG_INSTALLER install -y -q
		sudo $PKG_INSTALLER -y -q groupinstall 'Development Tools'	
	fi
		
	if [ $PREP_FOR_AZURE == 'true' ]; then
		write-log "bright_cyan" ">>> Installing Azure Linux agent for ${DISTRO} <<<"
		if [[ $RELEASE == '6' ]]; then 
			sudo rpm -e --nodeps NetworkManager
		fi	
		sudo $PKG_INSTALLER install -y -q python-pyasn1 WALinuxAgent
		sudo systemctl enable waagent
	fi
	
	if [ $OPENLOGIC_REPO == 'true' ] && [ $DISTRO == 'centos' ]; then	
		if [ -f /etc/yum.repos.d/CentOS-Base.repo ]; then rm -rf /etc/yum.repos.d/CentOS-Base.repo ; fi
	
		if [[ $RELEASE == '7' ]]; then 
			curl -o "/etc/yum.repos.d/CentOS-Base.repo" https://raw.githubusercontent.com/hybridadmin/centos-azure/master/config/repo/CentOS-7-Base.repo
		else
			curl -o "/etc/yum.repos.d/CentOS-Base.repo" https://raw.githubusercontent.com/hybridadmin/centos-azure/master/config/repo/CentOS-6-Base.repo
		fi
	fi

	if [ "/etc/udev/rules.d/70-persistent-net.rules" -ef "/dev/null" ]; then
		write-log "bright_cyan" ">>> Persistent NET rules fix for /etc/udev/rules.d/70-persistent-net.rules already applied <<<"
	else
		write-log "bright_blue" ">>> Applying NET persistent rules fix for /etc/udev/rules.d/70-persistent-net.rules <<<"
	    rm -f /etc/udev/rules.d/70-persistent-net.rules && ln -s /dev/null /etc/udev/rules.d/70-persistent-net.rules
	fi

	if [ "/lib/udev/rules.d/75-persistent-net-generator.rules" -ef "/dev/null" ]; then
	   write-log "bright_cyan" ">>> NET Persistent rules fix for /lib/udev/rules.d/75-persistent-net-generator.rules already applied <<<"
	else
	   write-log "bright_blue" ">>> Applying NET Persistent rules fix for /dev/null /lib/udev/rules.d/75-persistent-net-generator.rules <<<"
	    rm -f /lib/udev/rules.d/75-persistent-net-generator.rules && ln -s /dev/null /lib/udev/rules.d/75-persistent-net-generator.rules
	fi

	## Config Timesource ## 
	if $PKG_INSTALLER list installed | grep -P "(chrony\..*64)" >/dev/null 2>&1; then
		write-log "bright_blue" ">>> NTP service installed <<<"
	else			
		write-log "bright_blue" ">>> Installing NTP service <<<"
        systemctl stop ntpd && systemctl disable ntpd && systemctl mask ntpd
		sudo $PKG_INSTALLER install -y -q chrony
	fi
	
    TIME_CONF="/etc/chrony.conf"
	if cat "${TIME_CONF}" | grep "centos|redhat" >/dev/null 2>&1; then
		write-log "bright_blue" ">>> Configuring NTP service <<<"		
		configure_ntp "${TIME_CONF}" "${DISTRO}"
	else
		write-log "green" ">>> NTP service already configured <<<"
	fi 

	if  cat /etc/sysconfig/network-scripts/ifcfg-eth0 | grep -P "HWADDR|UUID|IPV6|PROXY|BROWSER" >/dev/null 2>&1 ; then
		write-log "bright_blue" ">>> Removing HWADDR|UUID|IPV6|PROXY|BROWSER settings from eth0 config file <<<"
		cp /etc/sysconfig/network-scripts/ifcfg-eth0 "/etc/sysconfig/network-scripts/ifcfg-eth0.$(date "+%Y%m%d-%H%M%S")"
		sed -i '/UUID\|HWADDR\|IPV6\|PROXY\|BROWSER/d' /etc/sysconfig/network-scripts/ifcfg-eth0
	else
		write-log "green" ">>> HWADDR|UUID|IPV6|PROXY|BROWSER fix already applied to eth0 config file... Skipping <<<"
	fi

	if [ $ADD_POWERSHELL_DSC == 'true' ]; then
		if iptables -L INPUT | grep -P "5985|5986" >/dev/null 2>&1; then
			write-log "green" ">>> WSMAN rules already open in firewall <<<"
		else
			write-log "bright_blue" ">>> Applying WSMAN firewall rules <<<"
			if [ $RELEASE == '7' ]; then
				for i in  "${ALLOWED_SOURCES[@]}"; do
					sudo bash -c "firewall-offline-cmd --zone=public --add-rich-rule='rule family=ipv4 source address="$i" port port="5985-5986" protocol=tcp accept'"
				done
			else
				for i in "${ALLOWED_SOURCES[@]}"; do
					iptables -A INPUT -s $i -p tcp -m multiport --dports 5985:5986 -m state --state NEW -j ACCEPT
				done
			fi
		fi
			
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
	fi
	
	## Regular firewall rules
	if [ `iptables -L | grep -e "ACC.*" | grep -P "ssh|ntp|icmp"  | wc -l` -ge 4 ]; then
		write-log "green" ">>> ssh|icmp|ntp rules already open in firewall <<<"
	else
		write-log "bright_blue" ">>> Applying ssh|icmp|ntp firewall rules <<<"
		if [ $RELEASE == '7' ]; then
			firewall-offline-cmd --zone=public --add-service=ssh 
			firewall-offline-cmd --zone=public --add-service=ntp
		else
			iptables -A INPUT -p tcp --dport 22 -j ACCEPT
			iptables -A OUTPUT -p tcp --dport 123 -j ACCEPT
			iptables -A OUTPUT -p udp --dport 123 -j ACCEPT			
			iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
			iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
		fi
	fi
	
	if [ $MAINLINE_KERNEL == 'true' ]; then 
		rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
		
		if [ $RELEASE == '8' ]; then
			REPO_URL='https://www.elrepo.org/elrepo-release-8.0-1.el8.elrepo.noarch.rpm'
		elif [ $RELEASE == '7' ]; then 
			REPO_URL='https://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm'
		else
			REPO_URL='https://www.elrepo.org/elrepo-release-6-8.el6.elrepo.noarch.rpm'
		fi
		
		rpm -Uvh $REPO_URL
		yum --enablerepo=elrepo-kernel install kernel-ml

		## https://www.thegeekdiary.com/centos-rhel-7-change-default-kernel-boot-with-old-kernel/
		grub2-set-default 0
		##grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
	
	## Iptables Persistent Rules
	if [ $RELEASE == '7' ]; then
		firewall-cmd --reload && firewall-cmd --list-all
	else
		iptables-save > /etc/sysconfig/iptables
	fi

	if [ $HOLD_KERNEL_UPDATES == 'true' ]; then	
		if  cat /etc/yum.conf  | grep exclude >/dev/null 2>&1 ; then
			write-log "green" ">>> Kernel Updates already disabled <<<"
		else 
			write-log "bright_blue" ">>> Disabling Kernel updates <<<"
			echo "exclude=kernel*" >> /etc/yum.conf
		fi
	fi 	

	if [[ `cat /etc/yum/yum-cron.conf | grep 'apply_updates' | cut -d '=' -f 2` == "yes" ]]; then
		write-log "green" ">>> yum cron already configured <<<"
	else
		write-log "bright_blue" ">>> configuring yum cron <<<"
		sed -i 's/apply_updates.*/apply_updates=no/' /etc/yum/yum-cron.conf
        sudo systemctl enable yum-cron.service && sudo systemctl start yum-cron.service
	fi
    
	if [[ `cat /etc/yum.conf | grep 'installonly_limit' | cut -d '=' -f 2` -eq 2 ]]; then
		write-log "green" ">>> Installed Kernel limit already set <<<"
	else
		write-log "bright_blue" ">>> Applying Installed Kernel limit <<<"
		#crudini --set --verbose /etc/yum.conf main installonly_limit 2
		sed -i 's/installonly_limit.*/installonly_limit=2/' /etc/yum.conf
	fi
	
	if [[ `$PKG_INSTALLER list installed --showduplicates kernel | grep 'kernel' | wc -l` -le 2 ]]; then
		write-log "green" ">>> No Old Installed Kernels to remove. Skipping  <<<"
	else
		write-log "bright_blue" ">>> Removing Old Kernels <<<"
		sudo $PKG_INSTALLER list --showduplicates kernel
		package-cleanup --oldkernels --count=2
	fi
	
	if $PKG_INSTALLER list installed | grep "kexec-tools"  >/dev/null 2>&1; then
		write-log "green" ">>> Kdump already installed and configured... Skipping <<<"
	else
		write-log "bright_blue" ">>> Installing/Configuring Kdump <<<"
		sudo $PKG_INSTALLER install -y -q  kexec-tools
		chkconfig kdump on
	fi

	if  cat /proc/cmdline | grep "noop" >/dev/null 2>&1; then
		write-log "green" ">>> Kernel Parameters already set... Skipping <<<"
	else
		write-log "bright_blue" ">>> Setting Kernel Parameters...  <<<"
		#https://azure.microsoft.com/en-us/documentation/articles/virtual-machines-linux-create-upload-centos/		
		if [ $RELEASE == '6' ]; then
			GRUB_CONFIGS=("/etc/grub.conf" "/boot/efi/EFI/redhat/grub.conf" "/boot/efi/EFI/BOOT/BOOTX64.CONF" "/boot/grub/grub.conf")
		        for i in  "${GRUB_CONFIGS[@]}"; do
		            if [ -f $i ]; then
		               write-log "bright_blue" ">>> $i exists. applying new Kernel paramters <<<"
						sed -i '/hiddenmenu\|splashimage/d' $i
						sed -i -e 's/rhgb quiet/video=hyperv_fb:1024x768 elevator=noop numa=off/g' $i
						sed -i -e 's/crashkernel=auto/crashkernel=0M-2G:128M,2G-6G:256M,6G-8G:512M,8G-:768M/g' $i
		            fi
		        done
			if [ -f /boot/efi/EFI/grub/grub.cfg ]; then
				sed -i -e 's/vg_centos-lv_root ro/vg_centos-lv_root ro video=hyperv_fb:1024x768 elevator=noop numa=off/g' /boot/efi/EFI/grub/grub.cfg
				sed -i -e 's/crashkernel=auto/crashkernel=0M-2G:128M,2G-6G:256M,6G-8G:512M,8G-:768M/g' /boot/efi/EFI/grub/grub.cfg
			fi
		else
			#grubby --update-kernel=ALL --args="video=hyperv_fb:1024x768 elevator=noop numa=off" --remove-args="rhgb quiet"
			if [ -f /boot/efi/EFI/centos/grub.cfg ]; then
				sed -i -e 's/crashkernel=auto/crashkernel=0M-2G:128M,2G-6G:256M,6G-8G:512M,8G-:768M/g' /etc/default/grub
				sed -i -e 's/rhgb quiet/video=hyperv_fb:1024x768 elevator=noop numa=off zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=50 intel_pstate=disable/g' /etc/default/grub
				grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
			fi
		fi
	fi

	if [ $OPENLOGIC_REPO == 'true' ]; then
		#lisversion=$($PKG_INSTALLER list installed | grep -P "(^|\s)\microsoft-hyper-v.x86_64(?=\s|$)" | awk '{print $2}' | tr -d '[[:space:]]')
		write-log "bright_blue" ">>> Installing Linux Integration Services drivers for ${DISTRO} ${RELEASE} <<<"
		if [ $RELEASE == '6' ]; then			
			if $PKG_INSTALLER list installed | grep -P "(microsoft-hyper-v)" >/dev/null 2>&1; then
				write-log "green" ">>> Linux Integration Services drivers already installed <<<"
			else
				write-log "bright_blue" ">>> Installing Linux Integration Services drivers for ${DISTRO} ${RELEASE} <<<"
				sudo $PKG_INSTALLER -y -q install microsoft-hyper-v
			fi
		else
			if $PKG_INSTALLER list installed | grep -P "(hyperv-daemons)" >/dev/null 2>&1; then
				write-log "green" ">>> Linux Integration Services drivers already installed <<<"
			else
				write-log "bright_blue" ">>> Installing Linux Integration Services drivers for ${DISTRO} ${RELEASE} <<<"
				sudo $PKG_INSTALLER -y -q install hyperv-daemons
			fi
		fi
	else
		if $PKG_INSTALLER list installed | grep -P "(hyperv-daemons)" >/dev/null 2>&1; then
			write-log "green" ">>> Linux Integration Services drivers already installed <<<"
		else
			write-log "bright_blue" ">>> Installing Linux Integration Services drivers for ${DISTRO} ${RELEASE} <<<"
			sudo $PKG_INSTALLER -y -q install hyperv-daemons
		fi	
	fi
	
    SELINUX_STATUS=$(sestatus | grep "SELinux status" | awk '{print $3}')
	if [ $RELEASE == '6' ] && [[ $SELINUX_STATUS == "enabled" ]]; then
		if $PKG_INSTALLER list installed | grep "hyperv-daemons"  >/dev/null 2>&1; then
			write-log "bright_blue" ">>> Adding Selinux fix for Hyper-V daemons <<<"
			#semanage permissive -a hypervvssd_t 
			curl -o /usr/share/selinux/devel/hyperv-daemons.te "https://raw.githubusercontent.com/hybridadmin/cloud-tools/master/config/centos/selinux/hyperv-daemons.te"
			cd /usr/share/selinux/devel
			make -f /usr/share/selinux/devel/Makefile hyperv-daemons.pp
			semodule -s targeted -i hyperv-daemons.pp
		fi 	
    fi	

	if [ $RELEASE == '7' ]; then
		#https://noobient.com/2017/09/27/fixing-the-efi-bootloader-on-centos-7/
		#https://bugs.centos.org/view.php?id=15522
		if [ $MINOR_VERSION == '6' ]; then
			write-log "green" ">>> No UEFI boot modifications required. Skipping ... <<<"
		else		
			if [ ! -f /boot/efi/EFI/BOOT/grubx64.efi ]; then
				write-log "bright_blue" ">>> Applying Generation 2 VM fix for UEFI boot... <<<"
				cp /boot/efi/EFI/centos/grub* /boot/efi/EFI/BOOT 
				cp -r /boot/efi/EFI/centos/fonts /boot/efi/EFI/BOOT 
			fi
		fi		
	fi	
	
	if [ ! -f /etc/udev/rules.d/100-balloon.rules ]; then
	    	write-log "bright_yellow" ">>> Creating file /etc/udev/rules.d/100-balloon.rules and enabling Hyper-V Hot-Add Support <<<"
	    	touch /etc/udev/rules.d/100-balloon.rules
    		echo 'SUBSYSTEM=="memory", ACTION=="add", ATTR{state}="online"' > /etc/udev/rules.d/100-balloon.rules
	else
		if cat /etc/udev/rules.d/100-balloon.rules | grep 'online' >/dev/null 2>&1; then
			write-log "green" ">>> Hyper-V Hot-Add Support already enabled in file /etc/udev/rules.d/100-balloon.rules <<<"
		fi
	fi

	write-log "bright_yellow" ">>> Cleaning up packages <<<"
	sudo $PKG_INSTALLER -y -q upgrade 
	sudo $PKG_INSTALLER clean all
	#### END CENTOS ###

elif [ $DISTRO == 'ubuntu' ] || [ $DISTRO == 'debian' ]; then 
	#UBUNTU
	# https://peteris.rocks/blog/quiet-and-unattended-installation-with-apt-get/
	# https://docs.microsoft.com/en-us/azure/virtual-machines/linux/debian-create-upload-vhd
	CODE_NAME=$(lsb_release -cs)
	RELEASE=$(lsb_release -rs | cut -d '.' -f 1)
	
	write-log "bright_blue" ">>> DETECTED DISTRO: $DISTRO - RELEASE: ${RELEASE} - CODENAME: ${CODE_NAME} <<<"		

	if [[ $UPDATE_MIRROR_LIST == 'false' ]]; then
		write-log "green" ">>> Skipping Mirror List Update <<<"
	else
		write-log "bright_yellow" ">>> Updating Mirror List for ${DISTRO} ${CODE_NAME} <<<"
		cp /etc/apt/sources.list /etc/apt/sources.list.bak.$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		
		if [[ $DISTRO == 'debian' ]]; then 
			# Debian
			if [ $OPENLOGIC_REPO == 'true' ]; then DEB_MIRROR="debian-archive.trafficmanager.net"; else DEB_MIRROR="ftp.is.co.za"; fi
			truncate -s 0 /etc/apt/sources.list
			echo "deb http://${DEB_MIRROR}/debian ${CODE_NAME}-updates main" >> /etc/apt/sources.list
			echo "deb-src http://${DEB_MIRROR}/debian ${CODE_NAME}-updates main" >> /etc/apt/sources.list
			echo "deb http://${DEB_MIRROR}/debian ${CODE_NAME}-backports main" >> /etc/apt/sources.list
			echo "deb-src http://${DEB_MIRROR}/debian ${CODE_NAME}-backports main" >> /etc/apt/sources.list			
		else
			# Ubuntu 
			MIRROR=$(curl -s http://mirrors.ubuntu.com/mirrors.txt | head -n1 | rev | cut -c 2- | rev)
			sed -i -e "s#http://archive.ubuntu.com/ubuntu/#${MIRROR}\/#g" /etc/apt/sources.list
		fi
	fi

	write-log "bright_yellow" ">>> Updating APT cache <<<"
	sudo $PKG_INSTALLER update -qqy
	write-log "bright_yellow" ">>> Updating System <<<"
	if [ $CODE_NAME == 'precise' ]; then
		sudo $PKG_INSTALLER DISTRO-upgrade -qqy 
	else
		sudo $PKG_INSTALLER upgrade -qqy 
	fi

	if [ $CODE_NAME == 'bionic' ]; then
		write-log "bright_yellow" ">>> Installing yq[YAML editing tool] package <<<"
		snap install yq
	fi
	
	if [ ! -z "$REQUIRED_PKGS" ]; then	
		write-log "bright_yellow" ">>> Installing required packages [$REQUIRED_PKGS] <<<"
		echo $REQUIRED_PKGS | xargs -P1 sudo $PKG_INSTALLER install -qqy
	fi
	
	if [ $PREP_FOR_AZURE == 'true' ]; then
		write-log "bright_cyan" ">>> Installing Azure Linux agent for ${DISTRO} <<<"
		if [ $DISTRO == 'debian' ]; then
			sudo $PKG_INSTALLER install -qqy waagent
		else	
			sudo $PKG_INSTALLER install -qqy walinuxagent
		fi	
	fi 

	if [ $ADD_POWERSHELL_DSC == 'true' ]; then
		if iptables -L INPUT | grep -P "5985|5986" >/dev/null 2>&1; then 
			write-log "green" ">>> WSMAN rules already open in firewall <<<"
		else
			write-log "bright_blue" ">>> Applying WSMAN firewall rules <<<"
			for i in "${ALLOWED_SOURCES[@]}"; do
				iptables -A INPUT -s $i -p tcp -m multiport --dports 5985:5986 -m state --state NEW -j ACCEPT
			done
		fi
			
		# https://gist.github.com/lukechilds/a83e1d7127b78fef38c2914c4ececc3c
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

	if [ `iptables -L | grep -e "ACC.*" | grep -P "ssh|ntp|icmp"  | wc -l` -ge 5 ]; then 	
		write-log "green" ">>> ssh|icmp|ntp rules already open in firewall <<<"
	else
		#http://dev-notes.eu/2016/08/persistent-iptables-rules-in-ubuntu-16-04-xenial-xerus/
		write-log "bright_blue" ">>> Applying ssh|icmp|ntp firewall rules <<<"
		iptables -A INPUT -p tcp --dport 22 -j ACCEPT
		iptables -A OUTPUT -p tcp --dport 123 -j ACCEPT
		iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
		iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
		iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
		iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	fi

	## Config Timesource 
    if [ $RELEASE -lt 16 ]; then    
        if dpkg -l | grep -P "(chrony)" >/dev/null 2>&1; then
            write-log "bright_blue" ">>> NTP service installed <<<"			
        else
            write-log "bright_blue" ">>> Installing NTP service <<<"
            systemctl stop ntp && systemctl disable ntp && systemctl mask ntp
            sudo $PKG_INSTALLER install -qqy chrony				
        fi
        
        TIME_CONF="/etc/chrony.conf"
        if cat "${TIME_CONF}" | grep "ubuntu|debian" >/dev/null 2>&1; then
            write-log "bright_blue" ">>> Configuring NTP service <<<"				
            configure_ntp "${TIME_CONF}" "${DISTRO}"
        else
            write-log "green" ">>> NTP service already configured <<<"
        fi
    else
        write-log "bright_blue" ">>> Configuring timesyncd service <<<"	
        sed -i "s/#NTP=.*/NTP=za.pool.ntp.org/g" /etc/systemd/timesyncd.conf
    fi

	if [ $DISTRO == 'ubuntu' ]; then
		if dpkg -l | grep -P "(linux-azure*|linux-generic-lts-trusty)" >/dev/null 2>&1; then
			write-log "green" ">>> Azure-tuned kernel already installed. Skipping <<<"		
		else
			if [ $CODE_NAME == 'precise' ]; then
				write-log "bright_blue" ">>> Starting Generic HWE kernel installation <<<"
				sudo $PKG_INSTALLER install -qqy linux-generic-lts-trusty 
			else
				write-log "bright_blue" ">>> Starting Azure-Tuned Kernel installation <<<"
				sudo $PKG_INSTALLER install -qqy linux-azure 
			fi
		fi
		
		if [ $CODE_NAME == 'precise' ]; then 
			if  dpkg -l | grep -P "(linux\-(tools|cloud-tools)\-virtual-lts-*|linux-(tools|cloud-tools)-*|hv-kvp-daemon-*)"	>/dev/null 2>&1; then
				write-log "green" ">>> Hyper-V KVP daemons already installed <<<"
			else
				write-log "bright_blue" ">>> Starting Hyper-V KVP Daemon installation. <<<"			
				sudo $PKG_INSTALLER install -qqy hv-kvp-daemon-init linux-tools-lts-trusty linux-cloud-tools-generic-lts-trusty 
			fi

			# hv_kvp_daemon fix for precise
			if [ $KVP_DAEMON_FIX == "true" ]; then
				if ps cax  | grep hv_kvp_daemon >/dev/null 2>&1; then
					write-log "green" ">>> Hyper-V KVP Daemon already running. Fix not required <<<"
				else
					write-log "bright_blue" ">>> Applying Hyper-V KVP Daemon Fix  <<<"
					sudo dpkg-divert --remove /usr/sbin/hv_kvp_daemon
					sudo mv /usr/sbin/hv_kvp_daemon /usr/sbin/hv_kvp_daemon.bak
					sudo mv /usr/sbin/hv_kvp_daemon.hv-kvp-daemon-init /usr/sbin/hv_kvp_daemon
					sudo service hv-kvp-daemon-init start
				fi
			fi
		fi
	else
		#Debian
		if [[ $PREP_FOR_AZURE == 'true' && $DISTRO == 'debian' ]]; then
			#if dpkg -l | grep -P "(linux-.*-cloud-amd64)" >/dev/null 2>&1; then
			if [ -f /etc/apt/preferences.d/linux.pref ]; then
				write-log "green" ">>> linux-image-cloud-amd64 package fix for Debian already applied <<<"
			else
				write-log "bright_blue" ">>> Installing linux-image-cloud-amd64 packages <<<"
				echo "Package: linux-* initramfs-tools" >> /etc/apt/preferences.d/linux.pref
				echo "Pin: release n=${CODE_NAME}-backports" >> /etc/apt/preferences.d/linux.pref
				echo "Pin-Priority: 500" >> /etc/apt/preferences.d/linux.pref
				sudo $PKG_INSTALLER install -qqy linux-image-cloud-amd64
			fi			
		fi
		
		if dpkg -l | grep -P "(hyperv-daemon-*)" >/dev/null 2>&1; then
			write-log "green" ">>> HyperV KVP daemons already installed <<<"
		else
			write-log "bright_blue" ">>> Installing HyperV KVP daemons <<<"
			sudo $PKG_INSTALLER install -qqy hyperv-daemons
		fi
	fi
		
	if [ $DISTRO == 'ubuntu' ]; then
		if [ $CODE_NAME == 'precise' ]; then
			write-log "bright_yellow" ">>> Gen 2 vm fix for UEFI boot not required. Distro is runnning in BIOS Mode <<<"
		else
			if [ ! -f /boot/efi/EFI/boot/bootx64.efi ]; then
				write-log "bright_blue" ">>> Applying UEFI Boot fix for Generation 2 Virtual Machines <<<"
				cd /boot/efi/EFI && sudo cp -r ubuntu/ boot
				cd boot && sudo mv shimx64.efi bootx64.efi
			else
				write-log "green" ">>> UEFI Boot fix for Generation 2 Virtual Machines already applied <<<"
			fi
		fi
	fi

	if  cat /proc/cmdline | grep "noop" >/dev/null 2>&1 ; then
		write-log "green" ">>> Kernel Parameters already set... Skipping <<<"
	else
		write-log "bright_blue" ">>> Setting Kernel Parameters ... <<<"
		#https://azure.microsoft.com/en-us/documentation/articles/virtual-machines-linux-create-upload-ubuntu/
		sed -i -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' /etc/default/grub
		sed -i -e 's/GRUB_CMDLINE_LINUX_DEFAULT=/GRUB_CMDLINE_LINUX_DEFAULT="video=hyperv_fb:1024x768 elevator=noop numa=off"/g' /etc/default/grub
		
		if [ $CODE_NAME == 'precise' ] || [ $DISTRO == 'debian' ]; then
			sed -i -e 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="crashkernel=0M-2G:128M,2G-6G:256M,6G-8G:512M,8G-:768M"/g' /etc/default/grub
		else 
			sed -i -e 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="crashkernel=0M-2G:128M,2G-6G:256M,6G-8G:512M,8G-:768M zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=50"/g' /etc/default/grub
			UPDATE_KERNEL_MODULES="true"
		fi
		
		if [ $CODE_NAME == 'bionic' ]; then
			if  cat /etc/default/grub | grep -E "GRUB_.+_TIMEOUT" >/dev/null 2>&1 ; then
				sed -i -e 's/GRUB_RECORDFAIL_TIMEOUT=.*/GRUB_RECORDFAIL_TIMEOUT=5/' /etc/default/grub
			else 
				echo "GRUB_RECORDFAIL_TIMEOUT=5" >> /etc/default/grub
			fi
		fi
		
		GRUB_UPDATE="true"
	fi

	if [ $CODE_NAME == 'bionic' ] && [ $ENHANCED_SESSION_MODE == "true" ] ; then
		write-log "bright_yellow" ">>> Enabling Enhanced Mode for Hyper-V <<<"
		#https://github.com/Microsoft/linux-vm-tools/tree/master/ubuntu/16.04
		sudo $PKG_INSTALLER install -qqy xrdp 
		sudo systemctl enable xrdp && sudo systemctl restart xrdp		
	fi

	if [ $HOLD_KERNEL_UPDATES == 'true' ]; then	
		dpkg -l "*$(uname -r)*" | grep kernel | awk '{print $2,"hold"}' | sudo dpkg --set-selections
	fi
	
	for USERNAME in $(ls /home) ; do
		write-log "bright_blue" ">>> Removing tmp user: ${USERNAME} <<<"
		deluser --remove-home $USERNAME
	done
	
    ## KEXEC
    if [ -f /etc/default/kexec ] && [ $RELEASE -ge '16' ]; then
        write-log "bright_yellow" ">>> Installing and configuring kexec <<<"
        if ! dpkg -l | grep kexec-tools | awk '{print $3}' | tr -d '[[:space:]]' >/dev/null 2>&1; then
            echo kexec-tools kexec-tools/load_kexec boolean true | sudo debconf-set-selections
            echo kexec-tools kexec-tools/use_grub_config boolean true | sudo debconf-set-selections
            sudo $PKG_INSTALLER -qqy install kexec-tools
        fi 
        #sed -i 's/^LOAD_KEXEC=.*/LOAD_KEXEC=true/' /etc/default/kexec
        #sed -i 's/^USE_GRUB_CONFIG=.*/USE_GRUB_CONFIG=true/' /etc/default/kexec    
	fi
    
	if [ $DISTRO == 'ubuntu' ]; then
		if dpkg -l | grep -P "(linux-crashdump)" >/dev/null 2>&1; then
			write-log "green" ">>> linux-crashdump Package already installed <<<"
		else
			write-log "bright_yellow" ">>> Installing linux-crashdump <<<"
			sudo apt install -qqy linux-crashdump
		fi
	fi
	
	if [ $CODE_NAME == 'precise' ] || [ $DISTRO == 'debian' ]; then
		if dpkg -l | grep -P "(kdump-tools)" >/dev/null 2>&1; then 
			write-log "green" ">>> kdump-tools Package already installed <<<"
		else
			write-log "bright_blue" ">>> Installing Kdump <<<"
            echo kdump-tools kdump-tools/use_kdump boolean true | sudo debconf-set-selections
			sudo $PKG_INSTALLER -qqy install kdump-tools
		fi	
	else
		write-log "bright_yellow" ">>> Skipping install of kdump-tools seperately. package already installed together with linux-crashdump <<<"
	fi
	
	if [ $DISTRO == 'ubuntu' ]; then
		if [ -f /etc/default/grub.d/kexec-tools.cfg ]; then 
			sed -i -e 's/.*GRUB_CMDLINE_LINUX_DEFAULT.*/GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT"/g' /etc/default/grub.d/kexec-tools.cfg
		fi
	fi
	
	if [ -f /etc/default/kdump-tools ] ; then
		if [ `cat /etc/default/kdump-tools | grep 'USE_KDUMP\=' | cut -d '=' -f 2` -eq 1 ]; then 
			write-log "green" ">>> Kdump Args already configured <<<"
		else
			write-log "bright_blue" ">>> Confguring Kdump Args <<<"
			sed -i -e 's/USE_KDUMP=0/USE_KDUMP=1/g' /etc/default/kdump-tools
			#kdump-config load && kdump-config show 
		fi
	fi

	if [[ $GRUB_UPDATE == "true" ]]; then
		write-log "bright_yellow" ">>> Updating Grub config <<<"
		update-grub
	fi
	
	if [[ $(cat /boot/config-* | grep ZSWAP | tail -n1 | rev | cut -c1) == "y" ]] && [[ $UPDATE_KERNEL_MODULES == "true" ]]; then 
		echo "lz4" >> /etc/modules && echo "lz4_compress" >> /etc/modules
		update-initramfs -u
	fi 
	
	# Iptables Persistent rules - https://gist.github.com/alonisser/a2c19f5362c2091ac1e7
	if [ `service netfilter-persistent status | tail -n 1 | cut -d ' ' -f6` == 'Started' ]; then 
		write-log "green" ">>> Iptables Persistent rules Active <<<"
	else
		write-log "bright_blue" ">>> Enabling Iptables Persistent rules <<<"
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
		sudo apt install -qqy iptables-persistent
		sudo service netfilter-persistent start && 	sudo invoke-rc.d netfilter-persistent save
	fi	
	
	write-log "bright_yellow" ">>> Cleaning up packages <<<"
	sudo $PKG_INSTALLER clean
	sudo $PKG_INSTALLER autoremove --purge -y

	write-log "bright_yellow" ">>> Cleaning up apt cache <<<"
	find /var/cache/apt/archives -type f -exec rm -vf \{\} \;
else 
	echo "Future Logic - Another distro"
fi

if [ $CLOUD_PART_TOOLS == 'true' ]; then	
	if [ $DISTRO == "centos" ]; then 
		write-log "bright_yellow" ">>> Installing Cloud Utils package [cloud-utils-growpart] <<<"
		sudo $PKG_INSTALLER -y -q install cloud-utils-growpart 
		if [ `df -Th | grep -w '/' | cut -d ' ' -f 2` == "zfs" ]; then
			sudo $PKG_INSTALLER -y -q install xfsprogs
		fi
	else
		if [ `lsb_release -cs` != 'bionic' ]; then
			write-log "bright_yellow" ">>> Installing Cloud Utils package [cloud-guest-utils ] <<<"
			sudo $PKG_INSTALLER -qqy install cloud-guest-utils
		fi
	fi 
fi

## SSH hardening
if [ `cat /etc/ssh/moduli | grep -P "\b2047\b" | wc -l` -gt 0 ]; then
    harden_ssh
fi 

if [ $BLACKLIST_MODULES == "true" ]; then
	BLACKLIST_CONF="/etc/modprobe.d/local-blacklist.conf"
	write-log "bright_yellow" ">>> Adding Blacklisted Modules to ${BLACKLIST_CONF} <<<"
	if [ ! -f "${BLACKLIST_CONF}" ]; then
		touch ${BLACKLIST_CONF}
	fi	
	echo "blacklist mdraid" >> ${BLACKLIST_CONF}
	
	if [ $DISTRO == "centos" ]; then 
		dracut -f		
	else
		update-initramfs -u
	fi
fi

write-log "bright_yellow" ">>> Cleaning up TMP/LOG/SEED folders <<<"
rm -vf /var/lib/urandom/random-seed
rm -rf /tmp/*
rm -rf /var/tmp/*
find /var/log -type f -name "*.gz" -exec rm -vf \{\} \;
find /var/log -type f -name "*.1" -exec rm -vf \{\} \;
find /var/log -type f -exec truncate -s0 \{\} \;

write-log "bright_yellow" ">>> Clearing Console history <<<"
cat /dev/null > "$HISTFILE" && history -cw

if [ $PREP_FOR_AZURE == 'true' ]; then	
	write-log "bright_cyan" ">>> Running Azure Linux Agent deprovisioning steps <<<"
	sudo sed -i 's/# AutoUpdate.Enabled=n/AutoUpdate.Enabled=y/g' /etc/waagent.conf
	sudo waagent -force -deprovision
	#export HISTSIZE=0
fi

write-log "bright_cyan" ">>> SYSPREP COMPLETE <<<"
# Self delete
if [[ $CURRENT_SCRIPT =~ \./ ]]; then
	SCRIPT_NAME=${CURRENT_SCRIPT##*/}
	SCRIPT_PATH=`dirname "$(readlink -f "$0")"`
	rm -- $SCRIPT_PATH/$SCRIPT_NAME
else
	rm -- "$0"
fi
####

