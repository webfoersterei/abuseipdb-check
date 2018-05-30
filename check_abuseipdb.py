#! /usr/bin/env python3

import sys
import ipaddress
import urllib.request
import simplejson
from optparse import OptionParser

VERSION='0.0.4-alpha'
USER_AGENT='abuseipdb_checkscript/%s (Python3/urllib; Github: webfoersterei)' % (VERSION)
TIMEOUT=5
BASEURL="https://www.abuseipdb.com/check/{}"

# From https://www.abuseipdb.com/categories
CATEGORY_NAMES={3: 'Fraud Orders', 4: 'DDoS Attack',
                9: 'Open Proxy', 10: 'Web Spam',
                11: 'Email Spam', 14: 'Port Scan',
                18: 'Brute-Force',19: 'Bad Web Bot',
                20: 'Exploited Host',21: 'Web App Attack',
                22: 'SSH', 23: 'IoT Targeted'}

# define exit codes
EXIT_OK = 0
EXIT_WARN = 1
EXIT_CRIT = 2
EXIT_UNKNOWN = 3

def abuseip_check(opts):
    exitCode = EXIT_UNKNOWN
    apiurl = BASEURL + '/json?key={}'    
    requestUrl = apiurl.format(opts.host, opts.key)
    headers = {'User-Agent': USER_AGENT}
    request = urllib.request.Request(requestUrl, None, headers)
    try:
        response = urllib.request.urlopen(request, timeout=TIMEOUT).read()
    except Exception:
        print('UNKNOWN - Problem querying API')
        sys.exit(exitCode)
    
    entries = simplejson.loads(response)

    if(len(entries) == 0):
        print("OK - No entries found")
        sys.exit(EXIT_OK)
    elif(len(entries) >= opts.criticalCount):
        print('CRITICAL', end=' - ')
        exitCode = EXIT_CRIT
    elif(len(entries) >= opts.warningCount):
        print('WARN', end=' - ')
        exitCode = EXIT_WARN
    else:
        # Its not 0 but also no threashold was reached
        print('OK', end=' - ')
        exitCode = EXIT_OK

    categories = set()
    for entry in entries:
        if len(entry['category']) > 0:
            for cat in entry['category']:
                categories.add(cat)
    
    categoryNames = []
    for category in categories:
        if category in CATEGORY_NAMES:
            categoryNames.append(CATEGORY_NAMES[category])

    print("Reported {0} times for: {1}".format(len(entries), ', '.join(categoryNames)))
    sys.exit(exitCode)
        


def main():
    parser = OptionParser("usage: %prog -H <IP address> -K <API key>")
    parser.add_option("-H","--hostaddress", dest="host", help="Specify the IP address you want to check")
    parser.add_option("-V","--version", action="store_true", dest="version", help="This option show the current version number of the program and exit")
    parser.add_option("-K", "--key", dest="key", help="API-key for abuseipdb.com")
    parser.add_option("-w", "--warn", dest="warningCount", default=1, type=int, help="Threshold for entries so that the return is a WARN")
    parser.add_option("-c", "--crit", dest="criticalCount", default=3, type=int, help="Threshold for entries so that the return is a CRIT")

    (opts, args) = parser.parse_args()
    if opts.version:
        print("check_abuseipdb.py %s"%VERSION)
        sys.exit()
    if not opts.key:
        print("API-key is mandatory")
        sys.exit()
    if opts.warningCount >= opts.criticalCount:
        print("Warning count should be less than criticalCount")
        sys.exit()
    if opts.host:
        try:
            ip = ipaddress.ip_address(opts.host)  
        except ValueError:
            parser.error("Incorrect IP Address.")
        abuseip_check(opts)
    else:
        print("Hostaddress is mandatory")
        sys.exit()
 
if __name__ == '__main__':
    main()