# AbuseIpDB checkscript

Checks if an IP-adress is listed on abuseipdb.com and why. For usage with nagios / icinga.

To use it periodically you need an API-Key from abuseipdb.com: https://www.abuseipdb.com/account#api-settings

I am not into python at all - so this script lacks all code standards that may exist for python.

## Requirements

- Python3
- PIP-Modules: urllib, simplejson

## Usage

```
python3 check_abuseipdb.py -H '127.0.0.1' -K 'MYSECRETAPIKEY'
```

Example Output
```
CRITICAL - Reported for: Port Scan, Brute-Force, Web App Attack, SSH
```

If it's WARN or CRIT is determined by optional parameters `--warn` (default: 1) and `--crit` (default: 3) that configure thresholds how many reports were filed against you.

Return code is:

- OK = 0
- WARN = 1
- CRIT = 2
- UNKNOWN = 3