#!/bin/bash

arg=$1

echo "[ + ] Enumeracao de Subdomains [ + ]"
echo

for domain in $(cat /data/$arg/dominios.txt);do
python3 /scripts/temp/parallel_subdomain_tmp.py $arg $domain
done
echo
