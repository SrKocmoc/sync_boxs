echo
echo [+] Delete index SUBDOMAIN TEMP
echo
curl -XDELETE --insecure --user admin:'68721948' https://localhost:9200/$1-subdomain-temp
echo
