#!/bin/bash
if [ $1 ];	then
	CN=$1
	echo "generating keys for $CN ..."
else
	echo "usage:\n sh generate_keys.sh with HOST_NAME or SERVER_IP\n"
	exit 1
fi

# https://wiki.strongswan.org/projects/strongswan/wiki/SimpleCA
mkdir -p ~/pki/{cacerts,certs,private}
chmod 700 ~/pki

if which ipsec >/dev/null 2>&1; then
    PKI_TOOL="ipsec"
else
    PKI_TOOL="strongswan"
fi

$PKI_TOOL pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-server-key.pem
$PKI_TOOL pki --self --ca --lifetime 3650 --in ~/pki/private/ca-server-key.pem --type rsa --dn "C=CH, O=strongSwan, CN=strongSwan CA, CN=$CN" --outform pem > ~/pki/cacerts/ca-server-cert.pem
echo -e 'CA certs at ~/pki.cacerts/ca-server-cert.pem\n'
$PKI_TOOL pki --print --in ~/pki/cacerts/ca-server-cert.pem

sleep 1
echo -e "\ngenerating server keys ..."
$PKI_TOOL pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/vpn-server-key.pem
$PKI_TOOL pki --pub --in ~/pki/private/vpn-server-key.pem --type rsa | \
	$PKI_TOOL pki --issue --lifetime 1825 \
	--cacert ~/pki/cacerts/ca-server-cert.pem \
	--cakey ~/pki/private/ca-server-key.pem \
	--dn "C=CH, O=strongSwan, CN=strongSwan CA, CN=$CN" \
	--san $CN \
	--flag serverAuth --flag ikeIntermediate \
	--outform pem > ~/pki/certs/vpn-server-cert.pem
echo -e "vpn server cert at ~/pki/certs/vpn-server-cert.pem\n"
$PKI_TOOL pki --print --in ~/pki/certs/vpn-server-cert.pem

if [ -f ~/pki/private/vpn-server-key.pem ]; then
    ln -s ~/pki/private/vpn-server-key.pem  /etc/swanctl/private/privkey.pem
fi

if [ -f ~/pki/certs/vpn-server-cert.pem ]; then
    ln -s ~/pki/certs/vpn-server-cert.pem   /etc/swanctl/x509/cert.pem
fi

if [ -f ~/pki/cacerts/ca-server-cert.pem ]; then
    ln -s ~/pki/cacerts/ca-server-cert.pem  /etc/swanctl/x509/ca-cert.pem
fi
