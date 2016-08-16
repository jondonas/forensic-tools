#!/bin/sh

if [ "x$1" = "x" ]; then
	echo "Usage: gather.sh [ ipaddress ]"
	exit
fi
PROGDIR=/home/jdonas/web-interface/components/ip-checker/scripts
$PROGDIR/ip-registrar.py $1
$PROGDIR/virustotal.py $1

sleep 1
