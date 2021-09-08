#!/bin/bash

# tested on ubuntu server 18.04
# Bash installation script to prepare a newly created instance to act as a phishing web/mail server

DOMAIN_NAME="$1"
VERIFICATION_EMAIL="$2"

if [ -z "$DOMAIN_NAME" ] || [ -z "$VERIFICATION_EMAIL" ]; then
  echo "Usage: $0 <domain-name> <verification-email>"
  exit 1
fi

sudo apt update &&
  sudo apt upgrade -y &&
  sudo apt install nginx python3 python3-pip certbot python3-certbot-nginx -y &&
  sudo certbot --domain $DOMAIN_NAME -m $VERIFICATION_EMAIL --non-interactive --nginx --agree-tos &&
  echo 'All done'
