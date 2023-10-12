import json
import socket
import subprocess
import sys
import uuid
from time import strftime
import requests

target = sys.argv[1]
domain = sys.argv[2]
headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
url = 'https://localhost:9200/' + target + '-subdomain-tmp/_doc?refresh'
auth = ('admin', '68721948')
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'assetfinder'
dic_subdomain = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target + '-' + x + '-assetfinder'
saida = 'assetfinder-' + x + '.txt'


def rdap_ip(ip):
    try:
        consulta1 = subprocess.check_output(
            f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 rdap {ip} --json || true',
            shell=True)
        json_rdap_ip = json.loads(consulta1)
        blocoip = json_rdap_ip['handle']
        return blocoip
    except:
        return ''


def rdap_domain(domain):
    nameserver = ''
    try:
        consulta2 = requests.get('https://rdap.registro.br/domain/' + domain)
        json_rdap = json.loads(consulta2.text)
        for ns in json_rdap['nameservers']:
            nameserver = nameserver + ns['ldhName'] + ','
        return nameserver[:-1]
    except:
        return ''


def executa():
    subprocess.check_output(
        f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 assetfinder -subs-only {domain} >> /data/{target}/tmp/{saida} || true',
        shell=True)


def parse():
    with open('/data/' + target + '/tmp/' + saida) as file:
        for line in file:
            dic_subdomain['timestamp'] = hora
            dic_subdomain['server.address'] = line.rstrip('\n')
            dic_subdomain['server.domain'] = line.rstrip('\n')
            try:
                dic_subdomain['server.ip'] = socket.gethostbyname(line.rstrip('\n'))
            except:
                dic_subdomain['server.ip'] = '0.0.0.0'
            dic_subdomain['vulnerability.scanner.vendor'] = scanner
            dic_subdomain['server.ipblock'] = rdap_ip(dic_subdomain['server.ip'])
            dic_subdomain['server.nameserver'] = rdap_domain(dic_subdomain['server.domain'])
            data = {
                '@timestamp': dic_subdomain['timestamp'],
                'server.address': dic_subdomain['server.address'],
                'server.domain': dic_subdomain['server.domain'],
                'server.ip': dic_subdomain['server.ip'],
                'server.ipblock': dic_subdomain['server.ipblock'],
                'server.nameserver': dic_subdomain['server.nameserver'],
                'vulnerability.scanner.vendor': dic_subdomain['vulnerability.scanner.vendor']
            }
            r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
            print(r.text)
            # print(data)


def main():
    executa()
    parse()


if __name__ == '__main__':
    main()
