#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")" || exit 1
source .ve/bin/activate
./hugin.py -r "$1" -i munin.ini  --csv-path "/dev/shm/$1.csv"
./parse_result.py "/dev/shm/$1.csv"

