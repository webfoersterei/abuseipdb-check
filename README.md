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

Parameters:
```
-V --version: show version and quit
-H --hostaddress: ip to check
-K --key: API-Key
-w --warn: Minimum reports to return a WARN (default: 1)
-c --crit: Minimum reports to return a CRIT (default: 3)
-d --days: Timespan to check in days (default: 14)
```

Example Output
```
CRITICAL - Reported 19x (last 14d) for: Port Scan, Brute-Force, Web App Attack, SSH
```

Return code is:

- OK = 0
- WARN = 1
- CRIT = 2
- UNKNOWN = 3