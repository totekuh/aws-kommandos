#!/bin/bash

sudo apt update &&
sudo apt install -y awscli python3 python3-pip &&
pip3 install -r requirements.txt &&
echo 'OK'