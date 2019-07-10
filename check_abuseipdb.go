package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

var version string
var compileDate string

const EXIT_CODE_OK = 0
const EXIT_CODE_WARN = 1
const EXIT_CODE_CRIT = 2
const EXIT_CODE_UNKNOWN = 3

type AbuseIpDbCheckResponse struct {
	Data AbuseIpDbCheckData `json:"data"`
}

type AbuseIpDbCheckData struct {
	IpAddress            string `json:"ipAddress"`
	IsPublic             bool   `json:"isPublic"`
	IpVersion            int    `json:"ipVersion"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	Isp                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	NumDistinctUsers     int    `json:"numDistinctUsers"`
	LastReportedAt       string `json:"lastReportedAt"`
}

func buildStatusMessage(totalReports int, totalUsers int, abuseScore int) string {
	return fmt.Sprintf("Found %d entries from %d users (Abuse Probability: %d%%)", totalReports, totalUsers, abuseScore)
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

	apiResult, err := getEntryCount(apiKey, address, daysToCheck)
	if err != nil {
		fmt.Println("UNKNOWN - Error: ", err)
		os.Exit(EXIT_CODE_UNKNOWN)
	}

	statusMessage := buildStatusMessage(apiResult.TotalReports, apiResult.NumDistinctUsers, apiResult.AbuseConfidenceScore)

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
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%d", *address, *daysToCheck)

	client := &http.Client{}

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
