#!/bin/sh

NAME=`ls /usr/lib/ | grep "python3." | head -n 1`

mkdir -p $1/lib/$NAME
cp -R /usr/local/lib/$NAME/* /root/env/lib/$NAME/
mkdir -p $1/bin 
cp -R /usr/local/bin/* /root/env/bin/



