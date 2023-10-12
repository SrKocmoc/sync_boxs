echo
echo "[+] Criando index SUBDOMAIN TEMP"
echo
curl -XPUT --insecure --user admin:'68721948' https://localhost:9200/$1-subdomain-temp -H "Content-Type: application/json" -d @- <<EOF
{
	"mappings":{
		"properties":{
		"@timestamp":{"type":"date"},
		"server.address": {"type":"keyword"},
		"server.domain": {"type":"keyword"},
                "server.nameserver": {"type":"keyword"},
		"server.ip": {"type":"ip"},
                "server.ipblock": {"type":"keyword"},
		"vulnerability.scanner.vendor": {"type":"keyword"}
		}
	}
}
EOF
echo
