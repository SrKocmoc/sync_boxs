import json
import requests
import uuid
from time import strftime
import subprocess
import sys

domain = sys.argv[1]  # Dominio
ip = sys.argv[2]      # IP
url = sys.argv[3]      # url
target = sys.argv[4]  # Target

# VAI FICAR  = python3 wayback_webenum.py businesscorp.com.br 37.59.174.225 http://businesscorp.com.br teste
dicionario = {}

url_tar = f"https://localhost:9200/{target}-webenum/_doc?refresh"
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = "waybackurls"
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-waybackurls"
saida = f"waybackurls-{x}.txt"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')


def executa(url_rec):
    result = subprocess.check_output(f'docker run --rm  --name {container_name} -v /data/{target}/tmp/:/data/ kali-tools:1.0 echo {url_rec} | waybackurls || true', shell=True)
    return result.decode('utf-8')[:-1].split('\n')


def parse():
    sistema = executa(domain)
    for sists in sistema:
        if sistema != '' or sistema != None:
            dicionario['network.protocol'] = sists.split(':')[0]
            try:
                dicionario['server.port'] = sists.split(':')[2].split('/')[0]
            except:
                if dicionario['network.protocol'] == 'http':
                    dicionario['server.port'] = 80
                else:
                    dicionario['server.port'] = '443'

            path = len(sists.split('/'))
            if path == 3:
                dicionario['url.path'] = '/'
                dicionario['url.original'] = sists
            else:
                i = 3
                dicionario['url.path'] = ''
                try:
                    dicionario['url.original'] = dicionario['network.protocol'] + '://' + sists.split('/')[2]
                except:
                    dicionario['url.original'] = dicionario['network.protocol'] + '://' + sists
                while i < path:
                    dicionario['url.path'] = dicionario['url.path'] + '/' + sists.split('/')[i]
                    i += 1
            data = {
                '@timestamp': hora,
                'server.address': domain,
                'server.domain': domain,
                'server.ip': ip,
                'server.port': dicionario['server.port'],
                'network.protocol': dicionario['network.protocol'],
                'url.path': dicionario['url.path'],
                'http.response.status_code': '200',
                'url.original': dicionario['url.original'],
                'url.full': dicionario['url.original']+dicionario['url.path'],
                'vulnerability.scanner.vendor': scanner
            }
            # print(data)
            r = requests.post(url_tar, auth=auth, headers=header, data=json.dumps(data), verify=False)
            print(r.text)


if __name__ == "__main__":
    parse()
