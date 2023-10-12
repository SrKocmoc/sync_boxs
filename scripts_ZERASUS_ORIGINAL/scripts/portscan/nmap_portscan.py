import sys
import xml.etree.ElementTree as ET
import requests
import subprocess
from time import strftime
import uuid
import json

# COMO FICARA: python3 nmap_portscan.py 192.168.0.9 teste
ip = sys.argv[1]
target = sys.argv[2]

dicionario = {}
url = f"https://localhost:9200/{target}-portscan/_doc?refresh"
url_get = f"https://localhost:9200/{target}-subdomain/_search"
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = "nmap"
x = str(uuid.uuid1()).split('-')[0]
container_name = f"{target}-{x}-nmap"
saida = f"nmap-{x}.xml"
header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
auth = ('admin', '68721948')


def executa():
    subprocess.check_output(
        f'docker run --name {container_name} --rm -v /data/{target}/tmp:/data kali-tools:1.0 nmap -sS -Pn -T4 {ip} -oX /data/{saida} || true',
        shell=True)


def consulta_ip(ip):
    data = {"size": 10000}
    get_doc = requests.get(url_get, headers=header, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)

    for x in parse_scan['hits']['hits']:
        if x['_source']['server.domain'] == str(ip):
            return x['_source']['server.ipblock']


def parse():
    arq = ET.parse(f'/data/{target}/tmp/{saida}')
    root = arq.getroot()

    for i in root.iter('nmaprun'):
        for nmap in i:
            if nmap.tag == "host":
                for host in nmap:
                    if host.tag == "address":
                        if ':' not in host.attrib['addr']:
                            dicionario['IP_v4'] = host.attrib['addr']
                            dicionario['network.type'] = host.attrib['addrtype']
                    if host.tag == "ports":
                        for port in host:
                            if port.tag == 'port':
                                dicionario['network.transport'] = port.attrib['protocol']
                                dicionario['server.port'] = port.attrib['portid']

                                for itens in port:
                                    if itens.tag == 'state':
                                        dicionario['service.state'] = itens.attrib['state']
                                    if itens.tag == 'service':
                                        dicionario['network.protocol'] = itens.attrib['name']
                                        try:
                                            dicionario['application.version.number'] = itens.attrib['version']
                                        except:
                                            dicionario['application.version.number'] = ''
                                        try:
                                            dicionario['service.name'] = itens.attrib['product']
                                        except:
                                            dicionario['service.name'] = ''

                                        dicionario['server.ipblock'] = consulta_ip(ip)
                                        data = {
                                            "@timestamp": hora,
                                            "server.address": ip,
                                            "network.protocol": dicionario['network.protocol'],
                                            "server.ip": ip,
                                            "server.port": dicionario['server.port'],
                                            "server.ipblock": dicionario['server.ipblock'],
                                            "server.name": dicionario['service.name'],
                                            "server.state": dicionario['service.state'],
                                            "network.transport": dicionario['network.transport'],
                                            "network.type": dicionario['network.type'],
                                            "application.version.number": dicionario['application.version.number'],
                                            "vulnerability.scanner.vendor": scanner
                                        }
                                        # print(data)

                                        r = requests.post(url, auth=auth, headers=header, data=json.dumps(data), verify=False)
                                        print(r.text)


if __name__ == "__main__":
    executa()
    parse()
