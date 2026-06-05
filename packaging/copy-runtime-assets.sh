#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 DESTINATION" >&2
  exit 2
fi

destination=$1

mkdir -p "$destination/domains"

cp config.example.json "$destination/"
cp config.mitm-domain-fronting.example.json "$destination/"
cp config.mitm-domain-fronting.example.json "$destination/config.json"
cp geoip.dat geosite.dat "$destination/"
cp domains/*.txt "$destination/domains/"
