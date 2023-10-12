import os
import sys
import requests
import json

target = sys.argv[1]
headers = {"Accept": "application/json", "Content-Type": "application/json"}
url = f"https://localhost:9200/{target}-webenum/_search"
auth = ("admin", "68721948")
dicionario = {}


def consulta_subdomain():
    data = {"size": 5000}
    get_doc = requests.get(url, auth=auth, headers=headers, verify=False, data=json.dumps(data))
    parse = json.loads(get_doc.text)

    for i in parse['hits']['hits']:
        if i['_source']['url.original'] not in dicionario:
            if str(i['_source']['url.original']) == '://':
                pass
            else:
                dicionario[i['_source']['url.original']] = [i['_source']['server.domain'], i['_source']['server.ip'], i['_source']['server.port'], i['_source']['network.protocol']]
    # print(dicionario)


def paraleliza():
    os.system(f'rm -rf /data/{target}/tmp/logs/gobuster_parallel.log')
    with open(f'/data/{target}/tmp/logs/gobuster_parallel.log', 'a') as file:
        for sub in dicionario:
            file.write(f"python3 /scripts/gobuster_webenum.py {dicionario[sub][0]} {dicionario[sub][1]} {sub} {sub.split(':')[0]} {dicionario[sub][2]} {target}\n")
    print('[ + ] Processando gobuster [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/gobuster_parallel.log | parallel -u')


if __name__ == "__main__":
    consulta_subdomain()
    paraleliza()
