#! /usr/bin/env python3

import sys
import ipaddress

from optparse import OptionParser
from AbuseIpDbChecker import AbuseIpDbChecker
from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

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
        print("check_abuseipdb.py %s"%AbuseIpDbChecker.VERSION)
        sys.exit()

    exitCode = AbuseIpDbChecker.EXIT_UNKNOWN
    checkOptions = normalizeOptions(opts.host, opts.key, opts.warningCount, opts.criticalCount, opts.days)

    try:
        checker = AbuseIpDbChecker()
        
        entries = checker.queryEntriesFromApi(checkOptions)
        
        if(type(entries) == dict):
            entries = [entries]
        
        exitCode = checker.analyseEntries(checkOptions, entries)
    except Exception as ex:
        print('UNKNOWN - Problem querying API: {0}'.format(ex))

    sys.exit(exitCode)
 
if __name__ == '__main__':
    main()
