# activeDNS
active DNS for mp


## AVRO SCHEMA PATTERN

```bash
#TODO for the reference
schema = {
    "namespace": "astrolavos.avro",
    "type": "record",
    "name": "ActiveDns",
    "fields": [
        {"name": "date", "type": "string"},
        {"name": "qname", "type": "string"},
        {"name": "qtype", "type": "int"},
        {"name": "rdata", "type": ["string", "null"]},
        {"name": "ttl", "type": ["int", "null"]},
        {"name": "authority_ips", "type": "string"},
        {"name": "count", "type": "long"},
        {"name": "hours", "type": "int"},
        {"name": "source", "type": "string"},
        {"name": "sensor", "type": "string"}
    ]
}
```

## History Data

```
1-and-1.com.do.	217.160.233.98
104layelectrical.com.	173.254.28.36
1135.com.	47.88.136.144
167thsignalco.com.	69.161.143.146
183128.pw.	141.8.226.58
18txl.tk.	195.20.45.18
2016gbc.org.	23.236.62.147
2020musiz.com.	104.154.95.49
24khotels.com.	61.152.175.8
28gaogao.com.	13.113.20.243
2aaccelerated.com.	205.178.189.131
2g.com.	104.18.60.94
39ers.de.	217.160.122.147
3d-4u.net.	216.239.36.21
5starfinishing.com.	198.185.159.144
66art.eu.	81.19.145.47
7airlines.ru.	45.76.92.34
```

## Squatting

We extend urlcrazy and DNStwist for more efficient squatting detection.

URLcrazy-0.5:  https://www.morningstarsecurity.com/research/urlcrazy

DNStwist: https://github.com/elceef/dnstwist

+ add combosquatting

+ add wrongTLD

+ add others

## Commands 

https://www.virustotal.com/en/url/fedfa28b317feda1399f28722016f421d2ccb9ae45bb7ac53b8aeeb628a2a595/analysis/

```bash
vt --url-report --url-scan /mnt/sdb1/mobilePhishing/DnsAnalysisEngine/dnsResovle/URL.txt

cat VT_report.txt| grep -n Positives/Total -A 5 -B 4
```