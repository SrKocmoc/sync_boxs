#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import sys
import datetime
import socket
import requests
import subprocess
import os
import uuid
import shutil
import json
import time
from time import strftime
from pathlib import Path

target = sys.argv[1]
domain = sys.argv[2]
headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
url = 'https://localhost:9200/' + target + '-subdomain-tmp/_doc?refresh'
auth = ('admin', '83d875fc-8789-11ec-9757-00505642c2bf')
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'subfinder'
dic_subdomain = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target + '-' + x + '-subfinder'
saida = 'subfinder-' + x + '.txt'


def rdap_ip(ip):
    try:
        consulta1 = subprocess.check_output(
            f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 rdap {ip} --json || true',
            shell=True)
        json_rdap_ip = json.loads(consulta1)
        blocoip = json_rdap_ip['handle']
        return (blocoip)
    except:
        return ('')


def rdap_domain(domain):
    nameserver = ''
    try:
        consulta2 = requests.get('https://rdap.registro.br/domain/' + domain)
        json_rdap = json.loads(consulta2.text)
        for ns in json_rdap['nameservers']:
            nameserver = nameserver + ns['ldhName']
        return (nameserver)
    except:
        return ('')


def executa():
    subprocess.check_output(
        f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 subfinder -d {domain} -oJ -silent >> /data/{target}/tmp/{saida} || true',
        shell=True)


def parse():
    with open('/data/' + target + '/tmp/' + saida) as json_file:
        for line in json_file:
            json_line = line.rstrip('\n')
            jsondata = json.loads(json_line)
            dic_subdomain['timestamp'] = hora
            dic_subdomain['server.address'] = jsondata['host']
            dic_subdomain['server.domain'] = jsondata['host']
            try:
                dic_subdomain['server.ip'] = socket.gethostbyname(jsondata['host'])
            except:
                dic_subdomain['server.ip'] = '0.0.0.0'
            dic_subdomain['vulnerability.scanner.vendor'] = scanner
            dic_subdomain['server.ipblock'] = rdap_ip(dic_subdomain['server.ip'])
            dic_subdomain['server.nameserver'] = rdap_domain(dic_subdomain['server.domain'])
            data = {
                '@timestamp': dic_subdomain['timestamp'],
                'server.address': dic_subdomain['server.address'],
                'server.domain': dic_subdomain['server.domain'],
                'server.ip': dic_subdomain['server.ip'],
                'server.ipblock': dic_subdomain['server.ipblock'],
                'server.nameserver': dic_subdomain['server.nameserver'],
                'vulnerability.scanner.vendor': dic_subdomain['vulnerability.scanner.vendor']
            }
            r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
            print(r.text)
            # print(data)


def main():
    executa()
    parse()


if __name__ == '__main__':
    main()
