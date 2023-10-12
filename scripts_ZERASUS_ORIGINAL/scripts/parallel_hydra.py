import sys

import requests
import os
import json

target = sys.argv[1]
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
url = f"https://localhost:9200/{target}-portscan/_search"
auth = ('admin', '68721948')

list_ip = []
list_server = []
dic_ip = {}
servicos = ['ftp', 'telnet', 'ssh', 'pop3', 'mysql', 'imap']


# COMO FICARA: python3 ssh 192.168.0.9 22 teste
def consulta():
    data = {"size": 10000}
    get_doc = requests.get(url, headers=header, auth=auth, verify=False, data=json.dumps(data))
    parse_scan = json.loads(get_doc.text)
    for i in parse_scan['hits']['hits']:
        if i['_source']['server.ip'] not in list_ip:
            list_ip.append(i['_source']['server.ip'])

    for x in list_ip:
        list_serv = []
        for c in parse_scan['hits']['hits']:
            if c['_source']['server.ip'] == x:
                if c['_source']['server.port'] not in list_serv:
                    list_serv.append(c['_source']['server.port'])
                    if c['_source']['server.port'] not in servicos:
                        if c['_source']['network.protocol'] in servicos:
                            with open(f"/data/{target}/tmp/logs/hydra_parallel.log", 'a') as file:
                                file.write(f"python3 /scripts/hydra_infravuln.py {c['_source']['network.protocol']} {x} {c['_source']['server.port']} {target}\n")


def parallel():
    print('[ + ] Processando HYDRA [ + ] ')
    os.system(f'cat /data/{target}/tmp/logs/hydra_parallel.log  | parallel -u')


if __name__ == "__main__":
    os.system(f"rm -rf /data/{target}/tmp/logs/hydra_parallel.log")
    consulta()
    parallel()
