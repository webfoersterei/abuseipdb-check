#! /usr/bin/env python3
import unittest

from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

class TestAbuseIpDbCheckOptions(unittest.TestCase):

    def test_allValid(self):
        options = AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)
        self.assertIsInstance(options, AbuseIpDbCheckOptions)
    
    def test_missingHostaddress(self):
        with self.assertRaisesRegex(ValueError, 'Hostaddress must be provided'):
            AbuseIpDbCheckOptions(None, 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)

    def test_notIpAtAllHostaddress(self):
        with self.assertRaisesRegex(ValueError, 'Hostaddress must be a parsable address'):
            AbuseIpDbCheckOptions('circusFooClown', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)

    def test_notValidIpv4Hostaddress(self):
        with self.assertRaisesRegex(ValueError, 'Hostaddress must be a valid IPv4-address'):
            AbuseIpDbCheckOptions('::1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)

    def test_missingApiKey(self):
        with self.assertRaisesRegex(ValueError, 'ApiKey must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', None, 2, 5, 14)

    def test_missingWarningThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Warning-Threshold must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', None, 5, 14)

    def test_notIntegerStringWarningThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Warning-Threshold must be an integer'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 'helloWorld', 5, 14)

    def test_zeroWarningThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Warning-Threshold must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 0, 5, 14)

    def test_negativeWarningThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Warning-Threshold must be greater than 0'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', -2, 5, 14)

    def test_missingCriticalThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Critical-Threshold must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, None, 14)

    def test_notIntegerStringCriticalThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Critical-Threshold must be an integer'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 'helloWorld', 14)

    def test_zeroCriticalThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Critical-Threshold must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 0, 14)

    def test_negativeCriticalThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Critical-Threshold must be greater than 0'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, -5, 14)

    def test_equalsCriticalWarningThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Warning-Threshold must be greater than Critical-Threshold'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 5, 5, 14)

    def test_greaterThanCriticalWarningThreshold(self):
        with self.assertRaisesRegex(ValueError, 'Warning-Threshold must be greater than Critical-Threshold'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 7, 5, 14)
    
    def test_missingDaysToQueryThreshold(self):
        with self.assertRaisesRegex(ValueError, '"Days to query" must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, None)

    def test_notIntegerStringDaysToQueryThreshold(self):
        with self.assertRaisesRegex(ValueError, '"Days to query" must be an integer'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 'helloWorld')

    def test_zeroDaysToQueryThreshold(self):
        with self.assertRaisesRegex(ValueError, '"Days to query" must be provided'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 0)

    def test_negativeDaysToQueryThreshold(self):
        with self.assertRaisesRegex(ValueError, '"Days to query" must be greater than 0'):
            AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, -14)

if __name__ == '__main__':
    unittest.main()