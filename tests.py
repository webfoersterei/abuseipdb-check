#! /usr/bin/env python3
import unittest
from AbuseIpDbCheckOptions import AbuseIpDbCheckOptions

class TestAbuseIpDbCheckOptions(unittest.TestCase):

    def test_inistanciate(self):
        options = AbuseIpDbCheckOptions(None, None, None, None, None)


if __name__ == '__main__':
    unittest.main()