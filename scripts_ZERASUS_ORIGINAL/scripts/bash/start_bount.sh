#!/bin/bash

arg=$1

echo "[ + ] INICIANDO BOUNTY - ENUMERACAO DE SUBDOMINIOS [ + ]"
echo
mkdir /data
mkdir /data/$arg/
mkdir /data/$arg/tmp/
mkdir /data/$arg/tmp/logs/
mkdir /scripts

echo "$arg" >> /dados/$arg/dominios.txt

for domain in /dados/$arg/dominios.txt:
do
    python3 /dados/scripts/parallel_subdomain.py $domain $arg
done
echo

echo "[ + ] INICIANDO BOUNTY - ENUMERACAO DE DIRETORIOS [ + ]"
echo
    python3 /scritps/parallel_gobuster.py $arg
echo

echo "[ + ] INICIANDO BOUNTY - ENUMERACAO DE URLs [ + ]"
echo
    python3 /scripts/parallel_waybackurl.py $arg
echo

echo "[ + ] INICIANDO BOUNTY - PORT SCANNING  [ + ]"
echo
    python3 /scripts/parallel_nmap.py $arg
echo


echo "[ + ] INICIANDO BOUNTY - SCAN DE VULNs WEB [ + ]"
echo
    python3 /scripts/parallel_nuclei.py $arg
    python3 /scripts/parallel_nikto.py $arg
echo

echo "[ + ] INICIANDO BOUNTY - SCAN VULNs INFRA [ + ]"
echo

   python3 /scripts/parallel_hydra.py $arg
echo

echo "[ + ] FINAL DO BOUNTY [ + ]"


