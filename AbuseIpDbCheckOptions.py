class AbuseIpDbCheckOptions(object):

    def __init__(self, hostaddress, apiKey, warningThreshold, criticalThreshold, daysToQuery):
        self.hostaddress = hostaddress
        self.apiKey = apiKey
        self.warningThreshold = warningThreshold
        self.criticalThreshold = criticalThreshold
        self.daysToQuery = daysToQuery
        self.validate()


    def validate(self):
        pass