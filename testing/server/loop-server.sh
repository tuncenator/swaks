#!/bin/bash

# loop-server.sh --silent -i 127.0.0.1 -p 8125 --cert ../certs/127_0_0_1.crt --key ../certs/127_0_0_1.key part-0201-intialize-tls.txt

DIR=`dirname $0`
SERVER=$DIR/smtp-server.pl

while true
do
  echo $SERVER $*
  $SERVER $*
  echo exited...
  read -t 5 -n 1 QUIT
  if [ ! -z "$QUIT" ] ; then
  	echo
    exit
  fi
done
