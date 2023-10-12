import json
import sys

import requests
import uuid
from time import strftime
import subprocess
import xml.etree.ElementTree as ET

url_completa = sys.argv[1]    # URL
target = sys.argv[2]          # Target

url = f"https://localhost:9200/{target}-webvuln/_doc?refresh"
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = "nikto"
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-nikto"
saida = f"nikto-{x}.xml"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')

dicionario = {}


def executa(url_rec):
    result = subprocess.check_output(
        f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 nikto -host {url_rec} -o /data/{saida} || true',
        shell=True)
    return result.decode('utf-8').replace(' ', '').split('\n')


def parse():
    global lista
    sistema = executa(url_completa)
    path = ET.parse(f'/data/{target}/tmp/{saida}')
    root = path.getroot()
    for i in root.iter('scandetails'):
        dicionario['server.ip'] = i.attrib['targetip']
        dicionario['server.address'] = i.attrib['targethostname']
        dicionario['server.domain'] = i.attrib['targethostname']
        dicionario['server.port'] = i.attrib['targetport']
        dicionario['network.protocol'] = i.attrib['sitename'].split(':')[0]
        dicionario['service.name'] = i.attrib['sitename'].split(':')[0]
        dicionario['http.response.status_code'] = '200'
        dicionario['url.original'] = url_completa

        for scan in i:
            if scan.tag == 'item':
                for item in scan:
                    if item.tag == 'description':
                        lista = [item.text.rstrip()]
                        dicionario['vulnerability.descripion'] = item.text.rstrip().replace('\n', ''),
                        dicionario['vulnerability.name'] = item.text.replace('()', ''),
                        dicionario['vulnerability.severity'] = 'N/A'
                    if item.tag == 'uri':
                        dicionario['url.path'] = item.text.replace('\n', '').replace('\n', '')
                    if item.tag == 'namelink':
                        dicionario['url.full'] = item.text.replace('\n', '').replace('\n', '')

                data = {
                    '@timestamp': hora,
                    'server.address': dicionario['server.address'],
                    'server.domain': dicionario['server.domain'],
                    'server.ip': dicionario['server.ip'],
                    'server.port': dicionario['server.port'],
                    'network.protocol': dicionario['network.protocol'],
                    'url.path': dicionario['url.path'],
                    'url.original': dicionario['url.original'],
                    'http.response.status_code': dicionario['http.response.status_code'],
                    'vulnerability.name': lista[0].replace(':', ''),
                    'vulnerability.description': lista[0],
                    'vulnerability.severity': dicionario['vulnerability.severity'],
                    'url.full': dicionario['url.full'],
                    'vulnerability.scanner.vendor': scanner
                }
                # print(data)
                r = requests.post(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
                print(r.text)


if __name__ == "__main__":
    parse()
