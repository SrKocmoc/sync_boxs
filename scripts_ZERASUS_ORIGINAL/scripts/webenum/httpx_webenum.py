import uuid
from time import strftime
import subprocess
import sys
import requests
import json

domain = sys.argv[1]  # Dominio
ip = sys.argv[2]      # IP
target = sys.argv[3]  # Target

# VAI FICAR  = python3 httpx_Automacao.py businesscorp.com.br 37.59.174.225 teste

dicionario = {}

url = f"https://localhost:9200/{target}-webenum/_doc?refresh"
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = "httpx"
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-httpx"
saida = f"httpx-{x}.txt"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')


def executa(url_rec):
    result = subprocess.check_output(f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data '
                                     f'kali-tools:1.0 httpx --silent -u {url_rec}|| true', shell=True)
    return result


def parse():
    sistema = executa(domain).decode('utf-8').rstrip()

    if sistema != sistema or sistema != None:
        dicionario['network.protocol'] = sistema.split(':')[0]
        try:
            dicionario['server.port'] = sistema.split(':')[2].split('/')[0]
        except:
            if dicionario['network.protocol'] == 'http':
                dicionario['server.port'] = 80
            else:
                dicionario['server.port'] = '443'

        path = len(sistema.split('/'))
        if path == 3:
            dicionario['url.path'] = '/'
            dicionario['url.original'] = sistema
        else:
            i = 3
            dicionario['url.path'] = ''
            dicionario['url.original'] = dicionario['network.protocol'] + sistema
            while i < path:
                dicionario['url.path'] = dicionario['url.path'] + sistema.split('/')[i]
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
            'url.full': dicionario['url.original'] + dicionario['url.path'],
            'vulnerability.scanner.vendor': scanner
        }

        # print(data)
        r = requests.post(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
        print(r.text)


if __name__ == "__main__":
    parse()
