package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"nowhere2hide"
	"nowhere2hide/utils"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type CensysHit struct {
	IP   string
	Port int
}

type CensysResponse struct {
	Code    int                  `json:"code"`
	Status  string               `json:"status"`
	Results CensysResponseResult `json:"result"`
}

type CensysResponseResult struct {
	Query string              `json:"query"`
	Total int                 `json:"total"`
	Hits  []CensysHits        `json:"hits"`
	Links CensysResponseLinks `json:"links"`
}

type CensysResponseLinks struct {
	Prev string `json:"prev"`
	Next string `json:"next"`
}

type CensysHitsServices struct {
	Port               int
	Service_Name       string
	Transport_Protocol string
	Certificate        string
}

type CensysHitsServicesLocationCoordinates struct {
	Latitude  string
	Longitude string
}

type CensysHitsServicesLocation struct {
	Continent               string
	Country                 string
	Country_Code            string
	Postal_Code             string
	Timezone                string
	Coordinates             CensysHitsServicesLocationCoordinates
	Registered_country      string
	Registered_country_code string
}

type CensysHitsAutonomous struct {
	ASN          int
	Description  string
	BGP_Prefix   string
	Name         string
	Country_Code string
}

type MatchedService struct {
	Service_Name          string
	Transport_Portocol    string
	Extended_Service_Name string
	Certificate           string
	Port                  int
}

type CensysHits struct {
	Name              string
	IP                string
	Services          []CensysHitsServices
	Location          CensysHitsServicesLocation
	Autonomous_system CensysHitsAutonomous
	Matched_Services  []MatchedService
}
type CensysRequest struct {
	Query         string
	PerPage       int
	Cursor        string
	Authorization string
}

type CENSYS struct{}

// Create a new instance of the logger.
var log = logrus.New()

// Logging Function
func (m CENSYS) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info(fmt.Sprintf("Collect|Error|Error Failed to log to file, using default stderr"))
	}
}

func (m CENSYS) Get_Name() string {
	return "censys"
}

func (m CENSYS) Run(c2_config *nowhere2hide.C2_Config, query string, runGUID string) []*nowhere2hide.Scan {

	m.Init()
	Target_Source_Identifier := "CENSYS"

	targets := m.Get_Targets(query, runGUID)

	var final_targets []*nowhere2hide.Scan

	for _, target := range targets {

		var zgrabScanTarget zgrab2.ScanTarget
		if target.Target_Type == "IP" {
			zgrabScanTarget.IP = net.ParseIP(target.Target)

			var temp nowhere2hide.Scan
			temp.Config = c2_config
			temp.Port = strconv.Itoa(target.Port)
			temp.Target = target.Target
			temp.ZTarget = zgrabScanTarget
			temp.Type = target.Target_Type
			temp.TargetSource = Target_Source_Identifier
			final_targets = append(final_targets, &temp)
		}
	}

	return final_targets
}

func (m CENSYS) Get_Targets(query string, runGUID string) []nowhere2hide.Target {

	var targets []nowhere2hide.Target

	api_keys, err := utils.LoadAPI()
	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|censys|Error|%s", runGUID, err))
		return targets
	}

	var cr CensysRequest

	cr.Query = query
	cr.PerPage = 100
	cr.Authorization = fmt.Sprintf("Basic %s", b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", api_keys.CENSYS_API_ID, api_keys.CENSYS_SECRET))))

	results := searchCensys(cr, runGUID)

	log.Info(fmt.Sprintf("Collect|%s|censys|Info|Query -> %s, Hits-> %d", runGUID, query, len(results)))

	for _, target := range results {
		var temp nowhere2hide.Target
		temp.Target_Type = "IP" // Type can be IP / Domain / URL
		temp.Target = target.IP
		temp.Port = target.Port
		targets = append(targets, temp)
	}

	return targets

}

var Collect CENSYS

func searchCensys(cr CensysRequest, runGUID string) []CensysHit {

	var CH []CensysHit
	res := getCensysHits(cr, runGUID)

	page := 2

	if res.Results.Total > 100 {
		pages := math.Ceil(float64(res.Results.Total) / float64(100))
		cr.Cursor = res.Results.Links.Next
		for _, hit := range res.Results.Hits {
			for _, service := range hit.Matched_Services {
				var temp CensysHit
				temp.IP = hit.IP
				temp.Port = service.Port
				CH = append(CH, temp)
			}
		}

		for page <= (int(pages)) {
			var temp CensysResponse
			temp = getCensysHits(cr, runGUID)
			cr.Cursor = temp.Results.Links.Next

			for _, hit := range temp.Results.Hits {
				for _, service := range hit.Matched_Services {
					var temp CensysHit
					temp.IP = hit.IP
					temp.Port = service.Port
					CH = append(CH, temp)
				}
			}
			page = page + 1
		}

	} else {
		for _, hit := range res.Results.Hits {
			for _, service := range hit.Matched_Services {
				var temp CensysHit
				temp.IP = hit.IP
				temp.Port = service.Port
				CH = append(CH, temp)
			}

		}

	}
	return CH
}

func getCensysHits(cr CensysRequest, runGUID string) CensysResponse {

	var res CensysResponse
	var url string

	if cr.Cursor == "" {
		url = fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s&per_page=%d", cr.Query, cr.PerPage)
	} else {
		url = fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s&per_page=%d&cursor=%s", cr.Query, cr.PerPage, cr.Cursor)
	}

	client := &http.Client{}

	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|censys|Error|%s", runGUID, err))
		return res
	}

	req.Header.Add("Authorization", cr.Authorization)

	resp, err := client.Do(req)

	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|censys|Error|%s", runGUID, err))
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|censys|Error|%s", runGUID, err))
		return res
	}

	json.Unmarshal([]byte(body), &res)

	return res

}
