import subprocess
import uuid
import requests
import json
import sys
from time import strftime

# COMO FICARA: python3 nuclei-webvuln-infra.py http://businesscorp.com.br businesscorp.com.br 80 /teste teste


address = sys.argv[1]
dominio = sys.argv[2]
porta = sys.argv[3]
path = sys.argv[4]
target = sys.argv[5]

dic_web = {}
dic_infra = {}

hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-nuclei"
saida = f"nuclei-{x}.json"
scanner = "nuclei"


def executa(uri):
    subprocess.check_output(f"docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 nuclei -u {uri} -o /data/{saida} -j || true", shell=True)


def parse():
    executa(address)
    with open(f'/data/{target}/tmp/{saida}') as file:
        for line_json in file:
            json_linha = line_json.rstrip()
            json_data = json.loads(json_linha)
            for i in json_data:
                if 'http' or 'https' in json_data['matched-at']:
                    url = f"https://localhost:9200/{target}-webvuln/_doc?refresh"
                    dic_web['vulnerability.name'] = json_data['info']['name']
                    dic_web['vulnerability.severity'] = json_data['info']['severity']
                    try:
                        dic_web['vulnerability.description'] = json_data['info']['description']
                    except:
                        dic_web['vulnerability.description'] = json_data['info']['name']
                    dic_web['url.original'] = json_data['host']
                    try:
                        dic_web['vulnerability.description'] = dic_web['vulnerability.description'] + ' ' + json_data['matcher-name']
                    except:
                         pass
                    dic_web['url.full'] = json_data['matched-at']
                    try:
                        dic_web['server.ip'] = json_data['ip']
                    except:
                        dic_web['server.ip'] = '0.0.0.0'

                    dic_web['reference'] = json_data['info']['reference']
                    dic_web['network.protocol'] = json_data['host'].split(':')[0]
                    dic_web['server.address'] = dominio
                    dic_web['server.domain'] = dic_web['server.address']
                    dic_web['server.port'] = porta
                    dic_web['url.path'] = path
                    dic_web['http.response.status_code'] = '200'

                    data = {
                        '@timestamp': hora,
                        'server.address': dic_web['server.address'],
                        'server.domain': dic_web['server.domain'],
                        'server.ip': dic_web['server.ip'],
                        'server.port': dic_web['server.port'],
                        'network.protocol': dic_web['network.protocol'],
                        'server.name': 'N/A',
                        'url.path': dic_web['url.path'],
                        'http.response.status_code': dic_web['http.response.status_code'],
                        'vulnerability.description': dic_web['vulnerability.description'],
                        'vulnerability.name': dic_web['vulnerability.name'],
                        'vulnerability.severity': dic_web['vulnerability.severity'],
                        'url.original': dic_web['url.original'],
                        'url.full': dic_web['url.full'],
                        'vulnerability.scanner.vendor': scanner
                    }
                else:
                    url = f'https://localhost:9200/{target}-infravuln/_doc?refresh'
                    dic_infra['server.address'] = dominio
                    dic_infra['vulnerability.name'] = json_data['info']['name']
                    dic_infra['vulnerability.severity'] = json_data['info']['severity']
                    try:
                        dic_infra['vulnerability.description'] = json_data['info']['description']
                    except:
                        dic_web['vulnerability.description'] = json_data['info']['name']
                    try:
                        dic_infra['vulnerability.description'] = dic_infra['vulnerability.description'] + ' ' + json_data['matcher-name']
                    except:
                        pass
                    try:
                        dic_infra['server.ip'] = json_data['ip']
                    except:
                        dic_infra['server.ip'] = '0.0.0.0'
                    try:
                        dic_infra['server.port'] = json_data['matched-at'].split(':')[1]
                    except:
                        dic_infra['server.port'] = porta
                    dic_infra['network.protocol'] = 'N/A'

                    if dic_infra['server.port'] == '21':
                        dic_infra['network.protocol'] = 'ftp'
                    elif dic_infra['server.port'] == '22':
                        dic_infra['network.protocol'] = 'ssh'
                    elif dic_infra['server.port'] == '23':
                        dic_infra['network.protocol'] = 'telnet'
                    elif dic_infra['server.port'] == '3389':
                        dic_infra['network.protocol'] = 'rdp'
                    elif dic_infra['server.port'] == '3306':
                        dic_infra['network.protocol'] = 'Mysql'

                    data = {
                            '@timestamp': hora,
                            'server.address': dic_infra['server.address'],
                            'server.ip': dic_infra['server.ip'],
                            'server.port': dic_infra['server.port'],
                            'network.protocol': dic_infra['network.protocol'],
                            'service.name': 'N/A',
                            'vulnerability.description': dic_infra['vulnerability.description'],
                            'vulnerability.name': dic_infra['vulnerability.name'],
                            'vulnerability.severity': dic_infra['vulnerability.severity'],
                            'vulnerability.scanner.vendor': scanner
                            }
            # print(data)
            r = requests.post(url=url, auth=auth, headers=header,  verify=False, data=json.dumps(data))
            print(r.text)


if __name__ == "__main__":
    parse()
