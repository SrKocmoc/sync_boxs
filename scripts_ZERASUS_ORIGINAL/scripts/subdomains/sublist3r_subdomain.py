import socket
import sys
from time import strftime
import json
import uuid
import requests
import subprocess

dominio = sys.argv[1]
target = sys.argv[2]

dicionario = {}
url = f"https://localhost:9200/{target}-subdomain/_doc?refresh"
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = "sublist3r"
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-sublist3r"
saida = f"sublist3r-{x}.txt"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')


def consulta_ip(ip):
    try:
        consulta1 = subprocess.check_output(
            f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 rdap {ip} --json || true',
            shell=True)
        json_rdap_ip = json.loads(consulta1)
        bloco = json_rdap_ip['handle']
        return bloco

    except:
        return ''


def rdap_domain(domain):
    nameserver = ''

    try:
        consulta2 = requests.get(f'https://rdap.registro.br/domain/{domain}')
        json_rdap = json.loads(consulta2.text)
        for ns in json_rdap['nameservers']:
            nameserver = nameserver + ns['ldhName'] + ','
        return nameserver[:-1]
    except:
        return ''


def executa():
    run = subprocess.check_output(
        f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 sublist3r -d {dominio} -o /data/{saida} || true',
        shell=True)


def parse():
    with open(f'/data/{target}/tmp/{saida}') as file:  # abrindo arquivo
        for linha in file:

            dicionario['server.domain'] = dominio
            dicionario['timestamp'] = hora
            try:
                if ':' in linha:
                    dicionario['server.address'] = linha.rstrip().split(':')[0]
                    dicionario['server.ip'] = socket.gethostbyname(linha.rstrip().split(':')[0])
                else:
                    dicionario['server.address'] = linha.rstrip()
                    dicionario['server.ip'] = socket.gethostbyname(linha.rstrip())
            except:
                dicionario['server.ip'] = '0.0.0.0'

            dicionario['vulnerability.scanner.vendor'] = scanner
            dicionario['server.ipblock'] = consulta_ip(dicionario['server.ip'])
            dicionario['server.nameserver'] = rdap_domain(dicionario['server.domain'])

            data = {
                '@timestamp': dicionario['timestamp'],
                'server.address': dicionario['server.address'],
                'server.domain': dicionario['server.domain'],
                'server.ip': dicionario['server.ip'],
                'server.ipblock': dicionario['server.ipblock'],
                'server.nameserver': dicionario['server.nameserver'],
                'vulnerability.scanner.vendor': dicionario['vulnerability.scanner.vendor']
            }
            # print(data)
            try:
                r = requests.post(url, data=json.dumps(data), headers=header, auth=auth, verify=False)
                print(r.text)
            except:
                pass


def main():
    executa()
    parse()


if __name__ == '__main__':
    main()
