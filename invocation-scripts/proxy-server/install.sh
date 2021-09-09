#!/bin/bash

# tested on ubuntu server 18.04

# Bash installation script to prepare a newly created instance to act as a SOCKS proxy
## change the service settings described below to use another port/IP address

MICROSOCKS_IP="$1"
MICROSOCKS_PORT="$2"

if [ -z "$MICROSOCKS_IP" ]; then
  echo "Setting 127.0.0.1 as default IP address"
  MICROSOCKS_IP="0.0.0.0"
fi
if [ -z "$MICROSOCKS_PORT" ]; then
  echo "Setting 42024 as default TCP port"
  MICROSOCKS_PORT=42024
fi

sudo apt update &&
  sudo apt upgrade -y &&
  sudo apt install git make build-essential -y &&
  echo "Installing microsocks"
cd ~/ &&
  git clone "https://github.com/derstolz/microsocks" &&
  cd microsocks &&
  make &&
  echo "Setting microsocks as a system service"
cat >/tmp/microsocks.service <<EOL
[Unit]
Description=Proxy Server
After=network.target

[Service]
Type=simple
RemainAfterExit=yes

ExecStart=/usr/bin/microsocks -i "MICROSOCKS_IP" -p "MICROSOCKS_PORT"
ExecStop=/usr/bin/killall microsocks

[Install]
WantedBy=multi-user.target
EOL

sed -i /tmp/microsocks.service -e "s|MICROSOCKS_IP|$MICROSOCKS_IP|" -e "s|MICROSOCKS_PORT|$MICROSOCKS_PORT|" &&

# in case it doesn't exist
sudo mkdir -p /usr/lib/systemd/system/ 2>/dev/null || echo "The system/ directory under systemd already exists"

sudo mv /tmp/microsocks.service /usr/lib/systemd/system/microsocks.service &&
  sudo chown root:root /usr/lib/systemd/system/microsocks.service &&
  sudo link ./microsocks /usr/bin/microsocks &&
  sudo systemctl daemon-reload &&
  sudo systemctl enable microsocks &&
  sudo systemctl start microsocks &&

PUBLIC_IP=$(curl -s ifconfig.co) &&
echo "All done. The proxy's available at $PUBLIC_IP:$MICROSOCKS_PORT"
