package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"nowhere2hide"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/guid"
	"gopkg.in/yaml.v2"
)

/*
Structs for UI processing, there may be some overlap between these structs and NOWHERE2Hide structs.
The goal is to separate UI from NOWHERE2HIDE where possible.
*/
var templates *template.Template

type C2_Record struct {
	IP             string
	Port           int
	Malware_Family string
	Rule_Name      string
	First_Seen     string
	Last_Seen      string
}

type C2_Count struct {
	Malware_Family string
	Count          int
}

type QueryResult struct {
	Columns []string        `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
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

type TempCollect struct {
	Source string
	Query  string
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

func getQueryHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	results, _ := store.ExecuteQuery(r.Form.Get("pg"), r.Form.Get("limit"), r.Form.Get("offset"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
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
	w.Write([]byte("Job started, go to job status page"))
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

	var collectors = []TempCollect{}
	var custom_detectors []string
	var createdDate string
	create := true

	for element, value := range r.Form {

		if element == "edited" {
			if value[0] == "true" {
				create = false
			}
		}

		if element == "Created_Date" {
			createdDate = value[0]

		}

		if element == "Rule_Name" {
			if strings.Contains(value[0], " ") {
				w.Write([]byte("Rule name cannot have spaces"))
				log.Info("UI Error -> Rule name cannot have spaces")
			} else {
				sig_config.Rule_Name = value[0]
			}

		}

		if element == "Update" {
			create = false
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

			var temp TempCollect
			if len(value) == 2 {
				temp.Source = value[0]
				temp.Query = value[1]
				collectors = append(collectors, temp)
			} else {
				temp.Source = value[0]
				collectors = append(collectors, temp)
			}
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

		if strings.Contains(element, "_custom_") {
			sig_config.Detection.Module = true
			custom_detectors = append(custom_detectors, value[0])
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

	if sig_config.Detection.Module == true {
		sig_config.Detection.Module_name = custom_detectors

	}

	var processed []string

	for _, tempCollect := range collectors {
		p := false
		for _, process := range processed {
			if process == tempCollect.Source {
				p = true
			}
		}
		if !p {
			var tempQueries []string
			for _, tc := range collectors {
				if tempCollect.Source == tc.Source {
					tempQueries = append(tempQueries, tc.Query)
				}
			}
			processed = append(processed, tempCollect.Source)
			var temp nowhere2hide.C2_Target
			temp.Source = tempCollect.Source
			temp.TargetQuery = tempQueries
			c2_targets = append(c2_targets, temp)
		}

	}
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
						sig_config.Scan_HTTP.RetryHTTPS = true
						sig_config.Scan_HTTP.FailHTTPtoHTTPs = false
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
	if create {
		sig_config.Created = t.Format("2006-01-02 15:04:05")
		sig_config.Last_Edit = t.Format("2006-01-02 15:04:05")

	} else {
		sig_config.Last_Edit = t.Format("2006-01-02 15:04:05")
		sig_config.Created = createdDate
	}

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
	w.Write([]byte("Success"))
	t = time.Now()
	log.Info(fmt.Sprintf("UI -> Config %s created at %s", sig_config.Rule_Name, t.Format("2006-01-02 15:04:05")))
}

func getRecordCountQHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	RecordCount, _ := store.GetRecordCountQ(r.Form.Get("query"))

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

func authHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	for element, value := range r.Form {
		if element == "c2-auth" {
			_, exists := store.CheckTokenExists(value[0])
			if exists {
				w.Write([]byte("Success"))
			} else {
				w.Write([]byte("Try again"))

			}
		}
	}

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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))
	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"index": "index"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func c2Handler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"c2": "c2"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func runscanHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"runscan": "runscan"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func queryHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"query": "query"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"status": "status"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func queryUIDHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	uid := r.Form.Get("uid")

	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err = templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"queryuid": "queryuid", "uid": uid})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func readmeHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"readme": "readme"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func utilitiesHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"utilities": "utilities"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func clearHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"cleardb": "cleardb"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func newsigHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"newsig": "newsig", "targets": getTargetSources(), "custom": getCustomDetection()})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func viewsigsHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"viewsigs": "viewsigs"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func editsigHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"editsig": "editsig", "targets": getTargetSources(), "custom": getCustomDetection()})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func logViewHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Execute the template
	err := templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"logview": "logview"})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func getLogHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()

	var filename string
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error parsing form"))
		log.Info(fmt.Sprintf("UI Error -> %s", err))
	}

	uid := r.Form.Get("uid")
	logType := r.Form.Get("logType")

	if logType == "run" {
		filename = "../logs/run.log"
	}

	if logType == "collect" {
		filename = "../logs/collect.log"
	}

	if logType == "scan" {
		filename = "../logs/scanner.log"
	}

	if logType == "detect" {
		filename = "../logs/detect.log"
	}

	file, _ := os.Open(filename)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var matches []string
	re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, uid))
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			matches = append(matches, line)
		}
	}

	logBytes, _ := json.Marshal(matches)
	w.Write(logBytes)

}
