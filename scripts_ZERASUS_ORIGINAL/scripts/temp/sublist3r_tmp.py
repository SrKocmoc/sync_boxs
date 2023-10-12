#!/usr/bin/env python3

import json
import socket
import subprocess
import sys
import uuid
from time import strftime
import requests

domain = sys.argv[1]
target = sys.argv[2]
headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
url = 'https://localhost:9200/' + target + '-subdomain-tmp/_doc?refresh'
auth = ('admin', '68721948')
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'sublist3r'
dicionario = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target + '-' + x + '-sublist3r'
saida = 'sublist3r-' + x + '.txt'


def consulta_ip(ip):
    try:
        consulta1 = subprocess.check_output(
            'docker run --rm --name ' + container_name + ' -v /data/' + target + ':/data kali-tools:1.0 rdap ' + ip + ' --json || true',
            shell=True)
        json_rdap_ip = json.loads(consulta1)
        blocoip = json_rdap_ip['handle']
        return blocoip
    except:
        return ''


def rdap_domain(domain):
    nameserver = ''
    try:
        consulta2 = requests.get('https://rdap.registro.br/domain/' + domain)
        json_rdap = json.loads(consulta2.text)
        for ns in json_rdap['nameservers']:
            nameserver = nameserver + ns['ldhName'] + ','
        return nameserver[:-1]
    except:
        return ''


def executa():
    subprocess.check_output(
        f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 sublist3r -d {domain} -o /data/{saida} || true',
        shell=True)


def parse():
    try:
        with open('/data/' + target + '/tmp/' + saida) as file:
            for linha in file:

                dicionario['server.domain'] = domain
                dicionario['timestamp'] = hora
                try:
                    if ':' in linha:
                        dicionario['server.address'] = linha.rstrip().split(':')[0]
                        dicionario['server.ip'] = socket.gethostbyname(linha.rstrip().split(':')[0])
                    else:
                        dicionario['server.address'] = linha.rstrip()
                        dicionario['server.ip'] = socket.gethostbyname(linha.rstrip())
                except:
                    dicionario['server.ip'] = '0.0.0.0'

                dicionario['vulnerability.scanner.vendor'] = scanner
                dicionario['server.ipblock'] = consulta_ip(dicionario['server.ip'])
                dicionario['server.nameserver'] = rdap_domain(dicionario['server.domain'])

                data = {
                    '@timestamp': dicionario['timestamp'],
                    'server.address': dicionario['server.address'],
                    'server.domain': dicionario['server.domain'],
                    'server.ip': dicionario['server.ip'],
                    'server.ipblock': dicionario['server.ipblock'],
                    'server.nameserver': dicionario['server.nameserver'],
                    'vulnerability.scanner.vendor': dicionario['vulnerability.scanner.vendor']
                }
                # print(data)
                try:
                    r = requests.post(url, data=json.dumps(data), headers=header, auth=auth, verify=False)
                    print(r.text)
                except:
                    pass
    except:
        executa()
        parse()


def main():
    executa()
    parse()


if __name__ == '__main__':
    main()
