'''

'''
import uuid
from time import strftime
import subprocess
import sys
import requests
import json


#  COMO FICARA: python3 gobuser.Automacao.py businesscorp.com.br 37.59.174.225 http://businesscorp.com.br http 80 teste
domain = sys.argv[1]         # Dominio
ip = sys.argv[2]             # IP
url_original = sys.argv[3]   # url
protocol = sys.argv[4]       # Protocolo
porta = sys.argv[5]
target = sys.argv[6]         # Target

dicionario = {}

url = f"https://localhost:9200/{target}-webenum/_doc?refresh"
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = "gobuster"
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-gobuster"
saida = f"gobuster-{x}.txt"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')


def executa(url_rec):
    result = subprocess.check_output(f'docker run --name {container_name} --rm -v /scripts/:/scripts kali-tools:1.0 gobuster dir -u {url_rec} -q -w /scripts/webdir.txt || true', shell=True)
    return result.decode('utf-8').replace(' ', '').split('\n')


def parse():
    sistema = executa(domain)
    for i in sistema:
        dicionario['server.address'] = domain
        dicionario['server.domain'] = domain
        dicionario['server.ip'] = ip
        dicionario['network.protocol'] = protocol
        dicionario['url.path'] = i.replace('\r\x1b[2K', '').split('(')[0]
        try:
            dicionario['http.response.status_code'] = i.split(':')[1].split(')')[0]
        except:
            dicionario['http.response.status_code'] = '200'
        dicionario['url.original'] = url_original
        dicionario['url.full'] = i+dicionario['url.path']
        dicionario['server.port'] = porta

        data = {
            '@timestamp': hora,
            'server.address': domain,
            'server.domain': domain,
            'server.ip': ip,
            'server.port': dicionario['server.port'],
            'network.protocol': dicionario['network.protocol'],
            'url.path': dicionario['url.path'],
            'http.response.status_code': dicionario['http.response.status_code'],
            'url.original': dicionario['url.original'],
            'url.full': dicionario['url.original'] + dicionario['url.path'],
            'vulnerability.scanner.vendor': scanner
        }

        # print(data)
        r = requests.post(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
        print(r.text)


if __name__ == "__main__":
    parse()
