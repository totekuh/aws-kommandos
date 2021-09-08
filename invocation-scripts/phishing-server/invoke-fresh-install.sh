#!/bin/bash

# tested on ubuntu server 18.04
# Bash installation script to prepare a newly created instance to act as a phishing web/mail server

DOMAIN_NAME="$1"

if [ -z "$DOMAIN_NAME" ]; then
  echo "Usage: $0 <domain-name>"
  exit 1
fi