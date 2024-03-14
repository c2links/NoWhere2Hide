package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"nowhere2hide"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/beevik/guid"
	"gopkg.in/yaml.v2"
)

/*
	Structs for UI processing, there may be some overlap between these structs and NOWHERE2Hide structs.
	The goal is to separate UI from NOWHERE2HIDE where possible.
*/

type C2_Record struct {
	IP             string
	Port           int
	Malware_Family string
}

type C2_Count struct {
	Malware_Family string
	Count          int
}

type Banner_Record struct {
	Address       string
	Port          string
	Status        string
	Banner_Hex    string
	Banner_Text   string
	Banner_Length int
	Timestamp     string
}

type Jarm_Record struct {
	Address     string
	Port        string
	Status      string
	Fingerprint string
	Timestamp   string
}

type TLS_Record struct {
	Address              string
	Port                 string
	Status               string
	Timestamp            string
	Version              int
	Serial_Number        string
	Issuer_Common_Name   string
	Issuer_Country       string
	Issuer_Organization  string
	Issuer_DN            string
	Subject_Common_Name  string
	Subject_Country      string
	Subject_Organization string
	Subject_DN           string
	Fingerprint_Md5      string
	Fingerprint_SHA1     string
	Fingerprint_SHA256   string
	JA4X                 string
}

type HTTP_Record struct {
	Address       string
	Port          string
	Status        string
	Status_Line   string
	Status_Code   int
	Protocol_Name string
	Headers       string
	Body          string
	Body_SHA256   string
	Timestamp     string
}

type Job_Status struct {
	UID                string
	Configs            string
	Job_Started        string
	Config_Validated   bool
	Targets_Acquired   bool
	Scan_Started       bool
	Scan_Finished      bool
	Detection_Started  bool
	Detection_Finished bool
	Job_Completed      string
	Errors             string
}

/*
These functions handle the API / HTTP requests from the UI and act as either the gateway to the NOWHERE2HIDE scanning engine or the Postgres database
that contains the scan data and C2 detections.

More information on what each on of these functions is responsible can be found in the "main.go" file.
*/

func getC2Handler(w http.ResponseWriter, r *http.Request) {

	C2List, _ := store.GetC2()

	c2ListBytes, err := json.Marshal(C2List)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(c2ListBytes)
}

func getC2ListHandler(w http.ResponseWriter, r *http.Request) {

	C2List, _ := store.GetC2List()

	c2ListBytes, err := json.Marshal(C2List)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(c2ListBytes)

}

func getC2QueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	C2List, _ := store.GetC2Query(r.Form.Get("malware"))

	c2ListBytes, err := json.Marshal(C2List)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(c2ListBytes)

}

func getBannerHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	BannerList, _ := store.GetBanner(r.Form.Get("limit"), r.Form.Get("offset"))

	bannerListBytes, err := json.Marshal(BannerList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	w.Write(bannerListBytes)

}

func getTLSHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	TLSList, _ := store.GetTLS(r.Form.Get("limit"), r.Form.Get("offset"))

	tlsListBytes, err := json.Marshal(TLSList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(tlsListBytes)

}

func getBannerQueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	BannerList, _ := store.GetBannerQuery(r.Form.Get("pg"), r.Form.Get("limit"), r.Form.Get("offset"))

	bannerListBytes, err := json.Marshal(BannerList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(bannerListBytes)
}

func getJarmHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	jarmList, _ := store.GetJarm(r.Form.Get("limit"), r.Form.Get("offset"))

	jarmListBytes, err := json.Marshal(jarmList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(jarmListBytes)

}

func getHTTPHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	httpList, _ := store.GetHTTP(r.Form.Get("limit"), r.Form.Get("offset"))

	httpListBytes, err := json.Marshal(httpList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(httpListBytes)

}

func getJarmQueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	jarmList, _ := store.GetJarmQuery(r.Form.Get("pg"), r.Form.Get("limit"), r.Form.Get("offset"))

	jarmListBytes, err := json.Marshal(jarmList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(jarmListBytes)

}

func getHTTPQueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	httpList, _ := store.GetHTTPQuery(r.Form.Get("pg"), r.Form.Get("limit"), r.Form.Get("offset"))
	httpListBytes, err := json.Marshal(httpList)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(httpListBytes)
}

func getTLSQueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	tlsList, _ := store.GetTLSQuery(r.Form.Get("pg"), r.Form.Get("limit"), r.Form.Get("offset"))
	tlsListBytes, err := json.Marshal(tlsList)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(tlsListBytes)
}

func getSigsHandler(w http.ResponseWriter, r *http.Request) {

	var configPaths []string

	err := filepath.WalkDir(runArgs.Signatures, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			configPaths = append(configPaths, d.Name())
		}
		return nil
	})

	if err != nil {
		sigListBytes, err := json.Marshal(configPaths)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Info(fmt.Sprintf("UI Error -> %s", err))
		}
		w.Write(sigListBytes)
	}

	sigListBytes, err := json.Marshal(configPaths)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(sigListBytes)

}

func getJobsHandler(w http.ResponseWriter, r *http.Request) {

	JobList, _ := store.GetJobs()
	jobListBytes, err := json.Marshal(JobList)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	w.Write(jobListBytes)
}

func getSigHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error parsing form"))
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	var config nowhere2hide.C2_Config

	filename := r.Form.Get("sig")

	yamlFile, err := os.ReadFile(fmt.Sprintf("%s/%s", runArgs.Signatures, filename))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error loading c2 config"))
		log.Info(fmt.Sprintf("UI Error -> %s", err))

	}
	err = yaml.Unmarshal(yamlFile, &config)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error b c2 config"))
		log.Info(fmt.Sprintf("UI Error -> %s", err))

	}

	sigBytes, _ := json.Marshal(config)
	w.Write(sigBytes)

}

func runScanHandler(w http.ResponseWriter, r *http.Request) {

	var configPaths []string

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	for sig, _ := range r.Form {
		configPaths = append(configPaths, sig)
	}

	t := time.Now()
	log.Info(fmt.Sprintf("UI -> Scan initiated at %s -> %s", t.Format("2006-01-02 15:04:05"), configPaths))
	Run(configPaths)

}

func addSigHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	var sig_config nowhere2hide.C2_Config
	var c2_targets []nowhere2hide.C2_Target
	var detections []nowhere2hide.Detection_Query

	var censys []string
	var shodan []string
	var badasn []string
	var newdomain []string
	var ipsum []string
	var tdomain []string

	//var binaryedge []string
	//var urlio []string

	for element, value := range r.Form {

		if element == "Rule_Name" {
			if strings.Contains(value[0], " ") {
				w.Write([]byte("Rule name cannot have spaces"))
				log.Info(fmt.Sprintf("UI Error -> Rule name cannot have spaces"))
			} else {
				sig_config.Rule_Name = value[0]
			}

		}

		if element == "Malware_Family" {
			sig_config.Family = value[0]
		}

		if element == "classification" {
			sig_config.Classification = value[0]
		}

		if element == "Description" {
			sig_config.Description = strings.Join(value, " ")
		}

		if element == "References" {
			var temp []string
			references := strings.Split(value[0], "\r\n")
			for _, reference := range references {
				temp = append(temp, reference)

			}

			sig_config.References = temp
		}

		if strings.Contains(element, "query") {
			if value[0] == "shodan" {
				shodan = append(shodan, value[1])
			}
			if value[0] == "censys" {
				censys = append(censys, value[1])
			}
			if value[0] == "badasn" {
				badasn = append(badasn, "enabled")
			}
			if value[0] == "newdomain" {
				newdomain = append(newdomain, "enabled")
			}
			if value[0] == "tdomain" {
				tdomain = append(tdomain, value[1])
			}
			if value[0] == "ipsum" {
				ipsum = append(ipsum, "enabled")
			}

			/*
				if value[0] == "binaryedge" {
					binaryedge = append(binaryedge, value[1])
				}
				if value[0] == "urlio" {
					urlio = append(urlio, value[1])
				}
			*/
		}

		if element == "TLS_Enabled" {
			if value[0] == "on" {
				sig_config.Scan_TLS = nowhere2hide.Scan_TLS{Enabled: true}

			}
		}

		if element == "JARM_Enabled" {
			if value[0] == "on" {
				sig_config.Scan_JARM = nowhere2hide.Scan_JARM{Enabled: true}

			}
		}

		if element == "HTTP_Enabled" {
			if value[0] == "on" {
				sig_config.Scan_HTTP = nowhere2hide.Scan_HTTP{Enabled: true}

			}
		}

		if element == "Banner_Enabled" {
			if value[0] == "on" {
				sig_config.Scan_Banner = nowhere2hide.Scan_Banner{Enabled: true}

			}
		}

		if element == "condition" {
			sig_config.Detection.Condition = value[0]
		}

		if element == "c2_plugin" {
			sig_config.Detection.Module = true
			sig_config.Detection.Module_name = value[0]

		}

		if strings.Contains(element, "detection") {

			sig_config.Detection.Simple = true
			var temp nowhere2hide.Detection_Query
			temp.Table = value[0]
			temp.Query = value[1]
			detections = append(detections, temp)

		}

	}

	if sig_config.Detection.Simple {
		sig_config.Detection.Queries = detections
	}

	var shodanTargets nowhere2hide.C2_Target
	var censysTargets nowhere2hide.C2_Target
	var badasnTargets nowhere2hide.C2_Target
	var newdomainTargets nowhere2hide.C2_Target
	var tdomainTargets nowhere2hide.C2_Target
	var ipsumTargets nowhere2hide.C2_Target

	// var binaryedgeTargets nowhere2hide.C2_Target
	// var urlioTargets nowhere2hide.C2_Target

	shodanTargets.Source = "shodan"
	shodanTargets.TargetQuery = shodan
	c2_targets = append(c2_targets, shodanTargets)

	censysTargets.Source = "censys"
	censysTargets.TargetQuery = censys
	c2_targets = append(c2_targets, censysTargets)

	badasnTargets.Source = "badasn"
	badasnTargets.TargetQuery = badasn
	c2_targets = append(c2_targets, badasnTargets)

	newdomainTargets.Source = "newdomain"
	newdomainTargets.TargetQuery = newdomain
	c2_targets = append(c2_targets, newdomainTargets)

	tdomainTargets.Source = "tdomain"
	tdomainTargets.TargetQuery = tdomain
	c2_targets = append(c2_targets, tdomainTargets)

	ipsumTargets.Source = "ipsum"
	ipsumTargets.TargetQuery = ipsum
	c2_targets = append(c2_targets, ipsumTargets)

	/*
		binaryedgeTargets.Source = "badasn"
		binaryedgeTargets.TargetQuery = binaryedge
		c2_targets = append(c2_targets, binaryedgeTargets)

		urlioTargets.Source = "urlio"
		urlioTargets.TargetQuery = urlio
		c2_targets = append(c2_targets, urlioTargets)
	*/
	sig_config.Targets = c2_targets

	if sig_config.Scan_Banner.Enabled {
		for element, value := range r.Form {
			if element == "banner_probe" {
				if len(value[0]) > 0 {
					sig_config.Scan_Banner.Probefile = value[0]
				}
			}
		}
	}

	if sig_config.Scan_HTTP.Enabled {

		var custom_headers []nowhere2hide.Custom_Header

		for element, value := range r.Form {

			if element == "http_useragent" {
				if len(value[0]) > 0 {
					sig_config.Scan_HTTP.Useragent = value[0]
				}
			}

			if element == "http_method" {
				if len(value[0]) > 0 {
					sig_config.Scan_HTTP.Method = value[0]
				}
			}

			if element == "http_endpoint" {
				if len(value[0]) > 0 {
					sig_config.Scan_HTTP.Endpoint = value[0]
				} else {
					sig_config.Scan_HTTP.Endpoint = "/"
				}
			}

			if element == "http_body" {
				if len(value[0]) > 0 {
					sig_config.Scan_HTTP.Body = value[0]
				}
			}

			if element == "http_https" {
				if len(value[0]) > 0 {
					if value[0] == "Yes" {
						sig_config.Scan_HTTP.HTTPS = true
						sig_config.Scan_HTTP.RetryHTTPS = false
						sig_config.Scan_HTTP.FailHTTPtoHTTPs = false
					} else {
						sig_config.Scan_HTTP.HTTPS = false
						sig_config.Scan_HTTP.RetryHTTPS = false
						sig_config.Scan_HTTP.FailHTTPtoHTTPs = true
					}
				}
			}

			if element == "http_headers" {

				headers := strings.Split(value[0], "\n")
				for _, header := range headers {
					header_kv := strings.Split(header, ":")
					if len(header_kv) > 1 {
						var temp nowhere2hide.Custom_Header
						temp.Field = header_kv[0]
						temp.Value = header_kv[1]
						custom_headers = append(custom_headers, temp)
					}

				}

				sig_config.Scan_HTTP.Custom_Headers = custom_headers

			}

		}
	}

	t := time.Now()

	sig_config.Created = t.Format("2006-01-02 15:04:05")
	sig_config.GUID = guid.New().String()

	yamlData, err := yaml.Marshal(&sig_config)
	if err != nil {
		w.Write([]byte(err.Error()))
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	filename := runArgs.Signatures + "/" + sig_config.Rule_Name + ".yml"

	err = os.WriteFile(filename, yamlData, 0777)
	if err != nil {
		w.Write([]byte(err.Error()))
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	w.Write([]byte("Created Successfully"))
	t = time.Now()
	log.Info(fmt.Sprintf("UI -> Config %s created at %s", sig_config.Rule_Name, t.Format("2006-01-02 15:04:05")))
}

func getRecordCountHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	RecordCount, _ := store.GetRecordCount(r.Form.Get("table"))

	RecordCountBytes, err := json.Marshal(RecordCount)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	w.Write(RecordCountBytes)

}

func getRecordCountQHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	RecordCount, _ := store.GetRecordCountQ(r.Form.Get("table"), r.Form.Get("query"))

	RecordCountBytes, err := json.Marshal(RecordCount)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}
	w.Write(RecordCountBytes)

}

func retroHandler(w http.ResponseWriter, r *http.Request) {

	s := RunRetro()
	w.Write([]byte(s))

}

func huntIOCertsHandler(w http.ResponseWriter, r *http.Request) {

	s := RunHuntCerts()
	w.Write([]byte(s))

}

func clearDBQueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	err = store.deleteContents(r.Form.Get("table"))

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
		w.Write([]byte(err.Error()))

	}

	w.Write([]byte("Successful"))

}
