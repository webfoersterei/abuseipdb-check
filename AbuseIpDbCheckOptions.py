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
            raise ValueError('Hostaddress must be provided')
        try:
            ip = ipaddress.ip_address(self.hostaddress)  
        except ValueError:
            raise ValueError('Hostaddress must be a parsable address')

        if(type(ip) != ipaddress.IPv4Address):
            raise ValueError('Hostaddress must be a valid IPv4-address')

        if(not self.apiKey):
            raise ValueError('ApiKey must be provided')

        if(not self.warningThreshold):
            raise ValueError('Warning-Threshold must be provided')

        try:
            int(self.warningThreshold)
        except ValueError:
            raise ValueError('Warning-Threshold must be an integer')

        if(self.warningThreshold <= 0):
            raise ValueError('Warning-Threshold must be greater than 0')

        if(not self.criticalThreshold):
            raise ValueError('Critical-Threshold must be provided')

        try:
            int(self.criticalThreshold)
        except ValueError:
            raise ValueError('Critical-Threshold must be an integer')

        if(self.criticalThreshold <= 0):
            raise ValueError('Critical-Threshold must be greater than 0')

        if(self.warningThreshold >= self.criticalThreshold):
            raise ValueError('Warning-Threshold must be greater than Critical-Threshold')

        if(not self.daysToQuery):
            raise ValueError('"Days to query" must be provided')

        try:
            int(self.daysToQuery)
        except ValueError:
            raise ValueError('"Days to query" must be an integer')

        if(self.daysToQuery <= 0):
            raise ValueError('"Days to query" must be greater than 0')
    
        pass