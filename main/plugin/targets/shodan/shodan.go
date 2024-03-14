package main

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"nowhere2hide"
	"nowhere2hide/utils"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/tomsteele/go-shodan"
	"github.com/zmap/zgrab2"
)

type ShodanRequest struct {
	Query         string
	Authorization string
}

type ShodanHit struct {
	IP   string
	Port int
}

type ShodanResponse struct {
	ShodanHits []ShodanHit
}

type SHODAN struct{}

// Create a new instance of the logger.
var log = logrus.New()

// Logging Function
func (m SHODAN) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info(fmt.Sprintf("Collect|shodan|Error|Failed to log to file, using default stderr"))
	}
}

func (m SHODAN) Get_Name() string {
	return "shodan"
}

func (m SHODAN) Run(c2_config *nowhere2hide.C2_Config, query string, runGUID string) []*nowhere2hide.Scan {

	m.Init()
	Target_Source_Identifier := "SHODAN"

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

func (m SHODAN) Get_Targets(query string, runGUID string) []nowhere2hide.Target {

	var targets []nowhere2hide.Target
	api_keys, err := utils.LoadAPI()
	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|shodan|Error|%s", runGUID, err))
		return targets
	}

	var sr ShodanRequest

	sr.Query = query
	sr.Authorization = api_keys.SHODAN

	results := searchShodan(sr)

	log.Info(fmt.Sprintf("Collect|%s|shodan|Info|Query -> %s, Hits-> %d", runGUID, query, len(results.ShodanHits)))

	for _, target := range results.ShodanHits {
		var temp nowhere2hide.Target
		temp.Target_Type = "IP" // Type can be IP / Domain / URL
		temp.Target = target.IP
		temp.Port = target.Port
		targets = append(targets, temp)
	}

	return targets

}

var Collect SHODAN

func searchShodan(sr ShodanRequest) ShodanResponse {

	c := shodan.New(sr.Authorization)
	opts := url.Values{}
	hs, _ := c.HostSearch(sr.Query, []string{}, opts)

	var sresp ShodanResponse
	page := 2

	if hs.Total > 100 {

		pages := math.Ceil(float64(hs.Total) / float64(100))

		for _, match := range hs.Matches {
			var temp ShodanHit
			temp.IP = match.IPStr
			temp.Port = match.Port
			sresp.ShodanHits = append(sresp.ShodanHits, temp)
		}

		for page <= (int(pages)) {

			opts.Set("page", strconv.Itoa(page))
			hs, _ = c.HostSearch(sr.Query, []string{}, opts)
			for _, match := range hs.Matches {
				var temp ShodanHit
				temp.IP = match.IPStr
				temp.Port = match.Port
				sresp.ShodanHits = append(sresp.ShodanHits, temp)
			}

			page = page + 1

		}
	} else {
		for _, match := range hs.Matches {
			var temp ShodanHit
			temp.IP = match.IPStr
			temp.Port = match.Port
			sresp.ShodanHits = append(sresp.ShodanHits, temp)
		}
	}

	return sresp
}
