# AbuseIpDB checkscript

Checks if an IP-adress is listed on abuseipdb.com and why. For usage with nagios / icinga.

To use it periodically you need an APIv2-Key from abuseipdb.com: https://www.abuseipdb.com/account/api

I am not into golang - so this script lacks all code standards that may exist.

## Usage

```
check_abuseipdb -key MYSECRETAPIKEY -host 127.0.0.1
```

Parameters:
```
-crit int
    Minimum reports to return a CRIT (default 3)
-days int
    Timespan to check in days (default 14)
-host string
    Host to check
-key string
    abuseipdb APIv2 key
-version
    Prints the version and exits
-warn int
    Minimum reports to return a WARN (default 1)
```

Output examples
* `OK - Found 0 entries from 0 users (Abuse Probability: 0%)` with exit code `0`
* `WARNING - Found 1 entries from 1 users (Abuse Probability: 4%) Port Scan, IoT Targeted` with exit code `1`
* `CRITICAL - Found 4 entries from 3 users (Abuse Probability: 34%) Email Spam, Hacking, Brute-Force` with exit code `2`
* `UNKNOWN - Error:  Get https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1: dial tcp: lookup api.abuseipdb.com: no such host` with exit code `3`


## CheckCommand Definition
Example config to integrate as checkCommand in icinga2 / nagios:
```
object CheckCommand "abuseipdb" {
        command = [ PluginDir + "/check_abuseipdb" ]

        arguments = {
                "-host" = {
                    value   =   "$address$"
                }
                "-key" = {
                    value   =   "$apikey$"
                }
                "-warn" = { 
                    value   =   "$warn_count$"
                }
                "-crit" = {
                    value   =   "$crit_count$"
                }
        }

        vars.address = "$check_address$"
        vars.apikey = "MYSECRETAPIKEY"
        vars.warn_count = 1
        vars.crit_count = 3
}
```