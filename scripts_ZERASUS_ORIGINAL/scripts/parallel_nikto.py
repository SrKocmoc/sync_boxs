import sys
import requests
import json
import os

target = sys.argv[1]
url = f"https://localhost:9200/{target}-webvuln/_search"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')

lista = []


def consulta_subdomain():
    data = {'size': 10000}
    get_doc = requests.get(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if x['_source']['url.original'] not in lista:
            lista.append(x['_source']['url.original'])
    # print(lista)


def paraleliza():
    os.system(f'rm -rf /data/{target}/tmp/logs/nikto_parallel.log')
    with open(f'/data/{target}/tmp/logs/nikto_parallel.log', 'a') as file:
        for sub in lista:
            file.write(f'python3 /scripts /nikto_webvuln.py {sub} {target}\n')

    print('[ + ] Processando Nikto [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/nikto_parallel.log | parallel -u')


if __name__ == "__main__":
    consulta_subdomain()
    paraleliza()
