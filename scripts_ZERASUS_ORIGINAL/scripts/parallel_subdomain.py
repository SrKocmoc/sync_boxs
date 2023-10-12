import os
import sys

dominio = sys.argv[1]
target = sys.argv[2]


def inicio():
    os.system(f'rm -rf /data/{target}/tmp/logs/subdomain_parallel.log')
    with open(f'/data/{target}/tmp/logs/subdomain_parallel.log', 'a') as file:
        file.write(f'python3 /scripts/assetfinder_subdomain.py {dominio} {target}\n')
        file.write(f'python3 /scripts/subfinder_subdomain.py {dominio} {target}\n')
        file.write(f'python3 ./sublist3r_subdomain.py {dominio} {target}\n')
    print("[ + ] PROCESSANDO SUBDOMAINS [ + ]")

    try:
        os.system(f'cat /data/{target}/tmp/logs/subdomain_parallel.log | parallel -u')
    except:
        os.system(f'cat /data/{target}/tmp/logs/subdomain_parallel.log | parallel -u')


if __name__ == "__main__":
    inicio()
