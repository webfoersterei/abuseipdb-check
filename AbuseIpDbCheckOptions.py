import ipaddress

class AbuseIpDbCheckOptions(object):

    def __init__(self, hostaddress, apiKey, warningThreshold, criticalThreshold, daysToQuery):
        self.hostaddress = hostaddress
        self.apiKey = apiKey
        self.warningThreshold = warningThreshold
        self.criticalThreshold = criticalThreshold
        self.daysToQuery = daysToQuery
        self.validate()


    def validate(self):
        if(not self.hostaddress):
            raise ValueError('Hostaddress must be set')
        try:
            ip = ipaddress.ip_address(self.hostaddress)  
        except ValueError:
            raise ValueError('Hostaddress must be a parsable address')

        if(type(ip) != ipaddress.IPv4Address):
            raise ValueError('Hostaddress must be a valid IPv4-address')
    
        pass