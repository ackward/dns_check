# dns-check

In any migration or Disaster Recovery (DR) process I always ask myself the same questions:

- Are all the DNS created, which ones are missing
- Do they target the right endpoint?
- Do they depend on from where are we trying to connect (local direct, local vpn, local zscaler, remote vpc,...)?
- Are FW and Proxy rules working for those endpoints?

This little script helps me identify what's missing and what isn't working.

## Exec

```bash
$ python3 dns-check.py -h
usage: dns-check.py [-h] [-f DNS_FILE] [--d] [--env ENV]

options:
  -h, --help   show this help message and exit
  -f DNS_FILE  DNS Excel file to check, default 'DNS_Entries.xlsx'
  --d          Enable Debug
  --env ENV    Environment
```

## Excel Format

Sheet Name: DNS_List
Columns:

![img_3.png](img_3.png)

- Env: environment, can be filtered with --env argument
- DNS: FQDN to check
- Type: A or CNAME
- Target: IP or FQDN depending on Type
- TCP: TCP port number or empty, if not empty check Target tcp connectivity to that port number
- Ping: TRUE/FALSE, if TRUE check Target supports ping/icmp 
- NS1: IP of Main DNS resolver
- NS2: can be empty or IP of Secondary DNS resolver

## Excel Report

Reports created on existing excel file as new sheets.
Sheet Name: CHECK_<env>_%Y%m%d%M%S
There's a conditional formatting (red row) on those which Status is not OK. 

![img_4.png](img_4.png)

- Env: environment
- DNS: FQDN to check
- Type: A or CNAME
- Target: IP or FQDN depending on Type
- NS: DNS Resolver used
- Status: Can be, MATCH (DNS, Type and Target exists and are OK), NO_EXIST (DNS doesn't exist or can't be resolved by NS), NO_MATCH (DNS and Target exist but don't match)
- TCP_Connectivity: OK or N/A if not available
- Ping: OK or N/A if not available
- DNS_ANSWER: The value obtained from NS
