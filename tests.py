#! /usr/bin/env python3
import unittest

from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

class TestAbuseIpDbCheckOptions(unittest.TestCase):

    def test_allValid(self):
        options = AbuseIpDbCheckOptions('127.0.0.1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)
        self.assertIsInstance(options, AbuseIpDbCheckOptions)
    
    def test_missingHostaddress(self):
        with self.assertRaisesRegex(ValueError, 'Hostaddress must be set'):
            AbuseIpDbCheckOptions(None, 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)

    def test_notIpAtAllHostaddress(self):
        with self.assertRaisesRegex(ValueError, 'Hostaddress must be a parsable address'):
            AbuseIpDbCheckOptions('circusFooClown', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)

    def test_notValidIpv4Hostaddress(self):
        with self.assertRaisesRegex(ValueError, 'Hostaddress must be a valid IPv4-address'):
            AbuseIpDbCheckOptions('::1', 'ashd7f38u4hfuebrfusda9wß', 2, 5, 14)

if __name__ == '__main__':
    unittest.main()