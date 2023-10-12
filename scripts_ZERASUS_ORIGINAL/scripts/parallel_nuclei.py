import os
import sys
import requests
import json

target = sys.argv[1]
url = f"https://localhost:9200/{target}-webenum/_search"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')
dicionario = {}


def consulta_subdomain():
    data = {'size': 10000}
    get_doc = requests.get(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if str(x['_source']['url.original'] not in dicionario):
            if str(x['_source']['url.original']) == '://':
                pass
            else:
                dicionario[x['_source']['url.original']] = [x['_source']['server.domain'], x['_source']['server.port'], x['_source']['url.path']]
    # print(dicionario)

# COMO FICARA: python3 nuclei-webvuln-infra.py http://businesscorp.com.br businesscorp.com.br 80 /teste teste


def paraleliza():
    os.system(f'rm -rf /data/{target}/tmp/logs/nuclei_parallel.log')
    with open(f'/data/{target}/tmp/logs/nuclei_parallel.log', 'a') as file:
        for sub in dicionario:
            file.write(f'python3 /scripts/nuclei-webvuln-infra.py {sub} {dicionario[sub][0]} {dicionario[sub][1]} {dicionario[sub][2]} {target}\n')
    print('[ + ] Processando Nuclei [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/nuclei_parallel.log | parallel -u')


if __name__ == "__main__":
    consulta_subdomain()
    paraleliza()
