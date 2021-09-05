#!/bin/bash

# Bash installation script to prepare a newly created instance to act as a SOCKS proxy
## change the service settings described below to use another port/IP address

sudo apt update &&
sudo apt install make git -y &&

echo "Installing microsocks"
cd ~/ &&
git clone "https://github.com/derstolz/microsocks" &&
cd microsocks &&
make &&
echo "Setting microsocks as a system service"
cat >microsocks.service <<EOL
[Unit]
Description=Proxy Server
After=network.target

[Service]
Type=simple
RemainAfterExit=yes

### CHANGE THIS
ExecStart=microsocks -i "0.0.0.0" -p 42024
ExecStop=killall microsocks

[Install]
WantedBy=multi-user.target
EOL

sudo chown root:root microsocks.service &&
sudo mv microsocks.service /usr/lib/systemd/system/microsocks.service &&
sudo link ./microsocks /usr/bin/microsocks &&

sudo systemctl daemon-reload &&
sudo systemctl enable microsocks &&
sudo systemctl start microsocks &&
echo "All done"
