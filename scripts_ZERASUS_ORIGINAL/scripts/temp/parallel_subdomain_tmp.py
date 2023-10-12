import os
import sys

target = sys.argv[1]
domain = sys.argv[2]


def parallel():
    os.system(f'rm -rf /data/{target}/tmp/subdomain_parallel_tmp.log')
    with open(f'/data/{target}/tmp/subdomain_parallel_tmp.log', 'a') as file:
        file.write(f'python3 /scripts/temp/assetfinder_tmp.py {target} {domain}\n')
        file.write(f'python3 /scripts/temp/subfinder_tmp.py {target} {domain} \n')
        file.write(f'python3 /scripts/temp/sublist3r_tmp.py {target} {domain}\n')
    print("[+] PROCESSANDO SUBDOMAIN \n")
    os.system(f'cat /data/{target}/tmp/subdomain_parallel_tmp.log | parallel -u')


def main():
    parallel()


if __name__ == '__main__':
    main()
