import os
import sys
import requests
import json

target = sys.argv[1]
url = f"https://localhost:9200/{target}-subdomain/_search"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')
lista = []


def consulta_subdomain():
    data = {'size': 10000}
    get_doc = requests.get(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if x['_source']['server.ip'] not in lista:
            lista.append(x['_source']['server.ip'])


def paraleliza():
    os.system(f'rm -rf /data/{target}/tmp/logs/nmap_parallel.log')
    for ip in lista:
        with open(f'/data/{target}/tmp/logs/nmap_parallel.log', 'a') as file:
            if ip == '0.0.0.0':
                pass
            else:
                file.write(f'python3 /scripts/nmap_portscan.py {ip} {target}\n')
    print('[ + ] Processando NMAP [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/nmap_parallel.log | parallel -u')


if __name__ == "__main__":
    consulta_subdomain()
    paraleliza()
