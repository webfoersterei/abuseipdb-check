package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

var version string
var compileDate string

const EXIT_CODE_OK = 0
const EXIT_CODE_WARN = 1
const EXIT_CODE_CRIT = 2
const EXIT_CODE_UNKNOWN = 3

var ABUSEIPDB_CATEGORIES = map[int]string{
	3: "Fraud Orders", 4: "DDoS Attack",
	5: "FTP Brute-Force", 6: "Ping of Death",
	7: "Phishing", 8: "Fraud VoIP",
	9: "Open Proxy", 10: "Web Spam",
	11: "Email Spam", 12: "Blog Spam",
	13: "VPN IP", 14: "Port Scan",
	15: "Hacking", 16: "SQL Injection",
	17: "Spoofing", 18: "Brute-Force",
	19: "Bad Web Bot", 20: "Exploited Host",
	21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}

type AbuseIpDbCheckResponse struct {
	Data AbuseIpDbCheckData `json:"data"`
}

type AbuseIpDbCheckData struct {
	IpAddress            string                 `json:"ipAddress"`
	IsPublic             bool                   `json:"isPublic"`
	IpVersion            int                    `json:"ipVersion"`
	IsWhitelisted        bool                   `json:"isWhitelisted"`
	AbuseConfidenceScore int                    `json:"abuseConfidenceScore"`
	CountryCode          string                 `json:"countryCode"`
	UsageType            string                 `json:"usageType"`
	Isp                  string                 `json:"isp"`
	Domain               string                 `json:"domain"`
	TotalReports         int                    `json:"totalReports"`
	NumDistinctUsers     int                    `json:"numDistinctUsers"`
	LastReportedAt       string                 `json:"lastReportedAt"`
	Reports              []AbuseIpDbCheckReport `json:"reports"`
}

type AbuseIpDbCheckReport struct {
	ReportedAt          string `json:"reportedAt"`
	Comment             string `json:"comment"`
	Categories          []int  `json:"categories"`
	ReporterId          int    `json:"reporterId"`
	ReporterCountryCode string `json:"reporterCountryCode"`
	ReporterCountryName string `json:"reporterCountryName"`
}

func buildStatusMessage(checkData AbuseIpDbCheckData) string {
	var reasonStr string

	if len(checkData.Reports) > 0 {
		var reasons = make(map[int]string) // Slice of *unique* reason strings
		for _, report := range checkData.Reports {
			for _, categoryId := range report.Categories {
				reasons[categoryId] = ABUSEIPDB_CATEGORIES[categoryId]
			}
		}

		for _, reason := range reasons {
			reasonStr += reason + ", "
		}
	}
	return strings.TrimRight(fmt.Sprintf("Found %d entries from %d users (Abuse Probability: %d%%) %s",
		checkData.TotalReports, checkData.NumDistinctUsers, checkData.AbuseConfidenceScore, reasonStr), ", ")
}

func main() {
	address := flag.String("host", "", "Host to check")
	apiKey := flag.String("key", "", "abuseipdb APIv2 key")
	daysToCheck := flag.Int("days", 14, "Timespan to check in days")
	warnCount := flag.Int("warn", 1, "Minimum reports to return a WARN")
	critCount := flag.Int("crit", 3, "Minimum reports to return a CRIT")
	versionPrint := flag.Bool("version", false, "Prints the version and exits")

	flag.Parse()

	if *versionPrint {
		fmt.Printf("Version %s (compiled at %s)\ngithub: https://github.com/webfoersterei/abuseipdb-check\n", version, compileDate)
		os.Exit(0)
	}

	if len(strings.Trim(*address, " ")) == 0 {
		fmt.Printf("Invalid arguments: No address provided: '%s'\n", *address)
		os.Exit(1)
	}

	if *warnCount > *critCount {
		fmt.Printf("Invalid arguments: WarnCount (%d) greater then CritCount (%d)\n", *warnCount, *critCount)
		os.Exit(1)
	}

	apiResult, err := getEntryCount(apiKey, address, daysToCheck)
	if err != nil {
		fmt.Println("UNKNOWN - Error: ", err)
		os.Exit(EXIT_CODE_UNKNOWN)
	}

	statusMessage := buildStatusMessage(apiResult)

	if apiResult.TotalReports >= *critCount {
		fmt.Printf("CRITICAL - %s", statusMessage)
		os.Exit(EXIT_CODE_CRIT)
	} else if apiResult.TotalReports >= *warnCount {
		fmt.Printf("WARNING - %s", statusMessage)
		os.Exit(EXIT_CODE_WARN)
	}

	fmt.Printf("OK - %s", statusMessage)
	os.Exit(EXIT_CODE_OK)
}

func getEntryCount(apiKey *string, address *string, daysToCheck *int) (AbuseIpDbCheckData, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%d&verbose=1", *address, *daysToCheck)

	client := &http.Client{
		Timeout: time.Second * 30,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return AbuseIpDbCheckData{}, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", *apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return AbuseIpDbCheckData{}, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return AbuseIpDbCheckData{}, err
	}

	response := AbuseIpDbCheckResponse{}
	json.Unmarshal(body, &response)

	return response.Data, err
}
