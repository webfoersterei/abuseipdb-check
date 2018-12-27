#! /usr/bin/env python3
import unittest
import simplejson

from AbuseIpDbChecker import AbuseIpDbChecker
from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

class TestAbuseIpDbCheck(unittest.TestCase):

    def loadFixtureEntries(self, filename):
        singleJsonContent = open(filename)
        entries = simplejson.load(singleJsonContent)
        singleJsonContent.close()

        if(type(entries) == dict):
            entries = [entries]

        return entries

    def test_analyseSingleEntry(self):
        entries = self.loadFixtureEntries('response_malicious-single.json')
        checkOptions = AbuseIpDbCheckOptions('127.0.0.1', 'helloWorld', 1, 2, 5)

        checker = AbuseIpDbChecker()
        self.assertEqual(AbuseIpDbChecker.EXIT_WARN, checker.analyseEntries(checkOptions, entries))

    def test_analyseMultipleEntries(self):
        entries = self.loadFixtureEntries('response_malicious-multiple.json')
        checkOptions = AbuseIpDbCheckOptions('127.0.0.1', 'helloWorld', 2, 4, 5)

        checker = AbuseIpDbChecker()
        self.assertEqual(AbuseIpDbChecker.EXIT_CRIT, checker.analyseEntries(checkOptions, entries))

    def test_analyseNoEntries(self):
        entries = []
        checkOptions = AbuseIpDbCheckOptions('127.0.0.1', 'helloWorld', 2, 4, 5)

        checker = AbuseIpDbChecker()
        self.assertEqual(AbuseIpDbChecker.EXIT_OK, checker.analyseEntries(checkOptions, entries))

    def test_analyseTooLessEntries(self):
        entries = self.loadFixtureEntries('response_malicious-single.json')
        checkOptions = AbuseIpDbCheckOptions('127.0.0.1', 'helloWorld', 2, 4, 5)

        checker = AbuseIpDbChecker()
        self.assertEqual(AbuseIpDbChecker.EXIT_OK, checker.analyseEntries(checkOptions, entries))

if __name__ == '__main__':
    unittest.main()