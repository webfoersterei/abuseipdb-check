#! /usr/bin/env python3

import sys
import ipaddress
import urllib.request
import simplejson
from optparse import OptionParser
from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

VERSION='0.1.0'
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

def queryEntriesFromApi(checkOptions: AbuseIpDbCheckOptions) -> object:
    ''' Will get entries from API and return an python object with all entries '''
    apiurl = BASEURL + '/json?key={}&days={}'    
    requestUrl = apiurl.format(checkOptions.hostaddress, checkOptions.apiKey, checkOptions.daysToQuery)
    headers = {'User-Agent': USER_AGENT}
    request = urllib.request.Request(requestUrl, None, headers)
    
    response = urllib.request.urlopen(request, timeout=TIMEOUT).read()

    return simplejson.loads(response)

def analyseEntries(checkOptions: AbuseIpDbCheckOptions, entries: list) -> int:
    ''' Will print some information and return the exit code '''
    if(len(entries) == 0):
        print("OK - No entries found")
        sys.exit(EXIT_OK)
    elif(len(entries) >= checkOptions.criticalThreshold):
        print('CRITICAL', end=' - ')
        exitCode = EXIT_CRIT
    elif(len(entries) >= checkOptions.warningThreshold):
        print('WARN', end=' - ')
        exitCode = EXIT_WARN
    else:
        # EntryCount is not 0 but also no threshold was reached
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

    print("Reported {0}x (last {1}d) for: {2}".format(len(entries), checkOptions.daysToQuery, ', '.join(categoryNames)))
    return exitCode

def normalizeOptions(hostaddress, apiKey, warningThreashold, criticalThreshold, daysToQuery):
    return AbuseIpDbCheckOptions(hostaddress, apiKey, warningThreashold, criticalThreshold, daysToQuery)

def main():
    parser = OptionParser("usage: %prog -H <IP address> -K <API key>")
    parser.add_option("-H","--hostaddress", dest="host", help="Specify the IP address you want to check")
    parser.add_option("-V","--version", action="store_true", dest="version", help="This option show the current version number of the program and exit")
    parser.add_option("-K", "--key", dest="key", help="API-key for abuseipdb.com")
    parser.add_option("-w", "--warn", dest="warningCount", default=1, type=int, help="Threshold for entries so that the return is a WARN")
    parser.add_option("-c", "--crit", dest="criticalCount", default=3, type=int, help="Threshold for entries so that the return is a CRIT")
    parser.add_option("-d", "--days", dest="days", default=14, type=int, help="Maximum age of reports to take into consideration")

    (opts, _) = parser.parse_args()

    if opts.version:
        print("check_abuseipdb.py %s"%VERSION)
        sys.exit()

    exitCode = EXIT_UNKNOWN
    checkOptions = normalizeOptions(opts.host, opts.key, opts.warningCount, opts.criticalCount, opts.days)
    
    try:
        entries = queryEntriesFromApi(checkOptions)
        
        if(type(entries) == dict):
            entries = [entries]
        
        exitCode = analyseEntries(checkOptions, entries)
    except Exception as ex:
        print('UNKNOWN - Problem querying API: {0}'.format(ex))
        sys.exit(EXIT_UNKNOWN)

    sys.exit(exitCode)
 
if __name__ == '__main__':
    main()
