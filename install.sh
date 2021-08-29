#!/bin/bash

sudo apt update &&
sudo apt install -y awscli python3 python3-pip &&
sudo link kommandos.py /usr/bin/aws-kommandos &&
chmod u+x kommandos.py &&
pip3 install -r requirements.txt &&
echo 'OK'