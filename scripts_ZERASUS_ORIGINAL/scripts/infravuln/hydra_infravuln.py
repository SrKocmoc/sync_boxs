import subprocess
import uuid
import requests
import json
import sys
from time import strftime

# COMO FICARA: python3 hydra_infravuln.py ssh 192.168.0.9 22 teste

service = sys.argv[1]
ip = sys.argv[2]
porta = sys.argv[3]
target = sys.argv[4]

dicionario = {}

hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-hydra"
url = f"https://localhost:9200/{target}-infravuln/_doc?refresh"
saida = f"hydra-{x}.json"
scanner = "hydra"


def executa(host, port, servico):
    subprocess.check_output(f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data -v /scripts:/scripts kali-tools:1.0 hydra -I -L /scripts/users.txt -P /scripts/passwords.txt -e nsr -o /data/{saida} -b json -t 1 {host} {servico} -s {port} || true', shell=True)


def parse():
    executa(host=ip, port=porta, servico=service)  # Ta recebendo os argumentos e passando para o executa.

    with open(f'/data/{target}/tmp/{saida}') as json_file:
        json_data = json.load(json_file)
        for i in json_data['results']:
            dicionario['server.address'] = i['host']
            dicionario['server.ip'] = ip
            dicionario['server.port'] = i['port']
            dicionario['network.protocol'] = i['service']
            dicionario['service.name'] = i['service']
            dicionario['vulnerability.description'] = f"Broken username/password {i['login']} : {i['password']}"
            dicionario['vulnerability.name'] = "Broken username/password"
            dicionario['vulnerability.severity'] = "High"

            data = {
                '@timestamp': hora,
                'server.address': dicionario['server.address'],
                'server.ip': dicionario['server.ip'],
                'server.port': dicionario['server.port'],
                'network.protocol': dicionario['network.protocol'],
                'service.name': 'N/A',
                'vulnerability.description': dicionario['vulnerability.description'],
                'vulnerability.name': dicionario['vulnerability.name'],
                'vulnerability.severity': dicionario['vulnerability.severity'],
                'vulnerability.scanner.vendor': scanner
            }

            # print(data)
            r = requests.post(url, auth=auth, data=json.dumps(data), headers=header, verify=False)
            print(r.text)


if __name__ == "__main__":
    parse()
