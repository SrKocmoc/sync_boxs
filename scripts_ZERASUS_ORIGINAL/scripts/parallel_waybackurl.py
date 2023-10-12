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
                dicionario[x['_source']['url.original']] = [x['_source']['server.domain'], x['_source']['server.ip']]
    # print(dicionario)


def paraleliza():
    os.system(f'rm -rf /data/{target}/tmp/logs/waybackurl_parallel.log')
    with open(f'/data/{target}/tmp/logs/waybackurl_parallel.log', 'a') as file:
        for sub in dicionario:
            file.write(f'python3 /scripts/wayback_webenum.py {dicionario[sub][0]} {dicionario[sub][1]} {sub} {target}\n')
    print('[ + ] Processando Waybackurl [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/waybackurl_parallel.log | parallel -u')


if __name__ == "__main__":
    consulta_subdomain()
    paraleliza()
