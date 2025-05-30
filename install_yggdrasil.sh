#!/bin/bash

# Install Yggdrasil from source
mkdir -p /tmp/yggdrasil-build
cd /tmp/yggdrasil-build
git clone https://github.com/yggdrasil-network/yggdrasil-go.git
cd yggdrasil-go
git checkout v0.5.12
./build
cp yggdrasil yggdrasilctl /usr/local/bin/
chmod +x /usr/local/bin/yggdrasil /usr/local/bin/yggdrasilctl
mkdir -p /etc/yggdrasil
/usr/local/bin/yggdrasil -genconf > /etc/yggdrasil/yggdrasil.conf
cd /
rm -rf /tmp/yggdrasil-build