#!/bin/bash
HOSTS_FILE="/root/hosts"
IP=`ip addr show eth0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1`
DOMID=`awk -v var=$IP -F- '$0 ~ var {print $2}' $HOSTS_FILE`
FILE="yasmin.c"

sed -i "s/#define LOCAL_ID .*/#define LOCAL_ID $DOMID/g" $FILE
