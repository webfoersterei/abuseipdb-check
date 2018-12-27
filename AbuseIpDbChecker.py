import urllib.request
import simplejson
from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

class AbuseIpDbChecker(object):
    VERSION='0.2.0'
    TIMEOUT=5
    USER_AGENT='abuseipdb_checkscript/%s (Python3/urllib; Github: webfoersterei)' % (VERSION)
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

    def queryEntriesFromApi(self, checkOptions: AbuseIpDbCheckOptions) -> object:
        ''' Will get entries from API and return an python object with all entries '''
        apiurl = self.BASEURL + '/json?key={}&days={}'    
        requestUrl = apiurl.format(checkOptions.hostaddress, checkOptions.apiKey, checkOptions.daysToQuery)
        headers = {'User-Agent': self.USER_AGENT}
        request = urllib.request.Request(requestUrl, None, headers)
        
        response = urllib.request.urlopen(request, timeout=self.TIMEOUT).read()

        return simplejson.loads(response)

    def analyseEntries(self, checkOptions: AbuseIpDbCheckOptions, entries: list) -> int:
        ''' Will print some information and return the exit code '''
        
        if(len(entries) == 0):
            print("OK - No entries found")
            return self.EXIT_OK
        elif(len(entries) >= checkOptions.criticalThreshold):
            print('CRITICAL', end=' - ')
            exitCode = self.EXIT_CRIT
        elif(len(entries) >= checkOptions.warningThreshold):
            print('WARN', end=' - ')
            exitCode = self.EXIT_WARN
        else:
            # EntryCount is not 0 but also no threshold was reached
            print('OK', end=' - ')
            exitCode = self.EXIT_OK

        categories = set()

        for entry in entries:
            if len(entry['category']) > 0:
                for cat in entry['category']:
                    categories.add(cat)
        
        categoryNames = []
        for category in categories:
            if category in self.CATEGORY_NAMES:
                categoryNames.append(self.CATEGORY_NAMES[category])

        print("Reported {0}x (last {1}d) for: {2}".format(len(entries), checkOptions.daysToQuery, ', '.join(categoryNames)))
        return exitCode