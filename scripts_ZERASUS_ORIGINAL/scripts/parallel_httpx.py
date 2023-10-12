import os
import sys

import requests
import json
import time

target = sys.argv[1]
hora = time.strftime("%Y-%m-%d-%H:%M:%S%Z")
url = f"https://localhost:9200/{target}-subdomain/_search"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')
dicionario = {}


def consulta_subdomain():
    data = {'size': 10000}
    get_doc = requests.get(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if str(x['_source']['server.domain'] not in dicionario and str(x['_source']['server.ip'] != '0.0.0.0')):
            dicionario[x['_source']['server.domain']] = x['_source']['server.ip']


def paraleliza():
    os.system(f'rm -rf /data/{target}/tmp/logs/httpx_parallel.log')
    with open(f'/data/{target}/tmp/logs/httpx_parallel.log', 'a') as file:
        for sub in dicionario:
            # VAI FICAR  = python3 httpx_Automacao.py businesscorp.com.br 37.59.174.225 teste
            file.write(f'python3 /scripts/httpx_webenum.py {sub} {dicionario[sub]} {target}\n')
    print('[ + ] Processando HTTPX [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/httpx_parallel.log | parallel -u')


if __name__ == "__main__":
    consulta_subdomain()
    paraleliza()
