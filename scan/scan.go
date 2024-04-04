package scan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	gohttp "net/http"
	"nowhere2hide"
	"nowhere2hide/db"
	"nowhere2hide/utils"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules"
	"github.com/zmap/zgrab2/modules/banner"
	"github.com/zmap/zgrab2/modules/http"
	"github.com/zmap/zgrab2/modules/jarm"
)

/*
The Scanner function takes the output from the collector and creates scans that are to be run against the targets.Scans are done using ZGRAB banner, HTTP, TLS or JARM  modules.

There are three parts to the code:


Part 1:

	The GO routines are fed the scan structs that are built in the collection phase. The structs define the type of scan, targets, ports, and flags related to the scan (options).
	The GO routine code is mainly based on how ZGRAB does it, with a few modifications.

Part 2:
	The specific fields from the scans are are parsed into a 'Response' struct that is used to the populate the Postgres database

Part 3:

	Scan results are are saved into the Postgres Database for detection phase
*/

// Create a new instance of the logger.
var log = logrus.New()

func init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/scanner.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("Scan|Error|Failed to log to file, using default stderr")
	}
}

func Run(scans []*nowhere2hide.Scan, scantype string, runGUID string) {

	if scantype == "zgrab2" {
		log.Info(fmt.Sprintf("Scan|%s|Info|Stating ZGRAB2 Scans", runGUID))
		outputQueue := zgrab2_scanner(scans, runGUID)
		zgrab2_add_scan_data(outputQueue, runGUID)
	}

	if scantype == "hunt_certs" {
		log.Info(fmt.Sprintf("Scan|%s|Info|Stating HUNT.IO Scans", runGUID))
		hunt_extract_certs(runGUID)
	}

}

func zgrab2_scanner(scans []*nowhere2hide.Scan, runGUID string) chan nowhere2hide.GeneralResponse {

	// Part 1
	var err error

	workers := 1000
	workerQueue := make(chan *nowhere2hide.Scan, (len(scans) + 10))
	outputQueue := make(chan nowhere2hide.GeneralResponse, (len(scans) + 10))

	//Create wait groups

	var workerDone sync.WaitGroup
	var outputDone sync.WaitGroup
	workerDone.Add(int(workers))
	outputDone.Add(1)

	log.Info(fmt.Sprintf("Scan|%s|Info|%d hosts added to scan que\n", runGUID, len(scans)))

	go func() {
		defer outputDone.Done()
	}()

	log.Info(fmt.Sprintf("Scan|%s|Info|Starting Go Routines\n", runGUID))

	for i := 0; i < workers; i++ {
		go func(i int) {

			for sj := range workerQueue {

				var response nowhere2hide.GeneralResponse
				log.Info(fmt.Sprintf("Scan|%s|Info|Scanning IP:PORT -> %s:%s", runGUID, sj.Target, sj.Port))

				moduleResult := make(map[string]zgrab2.ScanResponse)

				var e *string

				//TLS Scan
				if sj.Config.Scan_TLS.Enabled {
					var opts []string

					opts = append(opts, "tls")
					opts = append(opts, "--port")
					opts = append(opts, sj.Port)

					var flags zgrab2.ScanFlags
					_, _, flags, err = zgrab2.ParseCommandLine(opts)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					tlsModule := &modules.TLSModule{}
					tlsScanner := tlsModule.NewScanner()
					err := tlsScanner.Init(flags)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					status, results, _ := tlsScanner.Scan(sj.ZTarget)

					t := time.Now()

					// Grab and format the ZGRAB2 responses
					resp := zgrab2.ScanResponse{Result: results, Protocol: tlsScanner.Protocol(), Error: e, Timestamp: t.Format(time.RFC3339), Status: status}

					moduleResult[tlsScanner.GetName()] = resp
					raw := zgrab2.BuildGrabFromInputResponse(&sj.ZTarget, moduleResult)
					finalresult, _ := zgrab2.EncodeGrab(raw, true)
					json.Unmarshal(finalresult, &response)
					response.Port = sj.Port

				}

				// Jarm scan
				if sj.Config.Scan_JARM.Enabled {

					var opts []string
					opts = append(opts, "jarm")
					opts = append(opts, "--port")
					opts = append(opts, sj.Port)

					var jarmFlags zgrab2.ScanFlags
					_, _, jarmFlags, err = zgrab2.ParseCommandLine(opts)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					jarmModule := &jarm.Module{}
					jarmScanner := jarmModule.NewScanner()
					err := jarmScanner.Init(jarmFlags)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					status, results, _ := jarmScanner.Scan(sj.ZTarget)

					t := time.Now()

					// Grab and format the ZGRAB2 responses
					resp := zgrab2.ScanResponse{Result: results, Protocol: jarmScanner.Protocol(), Error: e, Timestamp: t.Format(time.RFC3339), Status: status}

					moduleResult[jarmScanner.GetName()] = resp
					raw := zgrab2.BuildGrabFromInputResponse(&sj.ZTarget, moduleResult)
					finalresult, _ := zgrab2.EncodeGrab(raw, true)
					json.Unmarshal(finalresult, &response)
					response.Port = sj.Port

				}

				if sj.Config.Scan_HTTP.Enabled {

					var opts []string
					opts = append(opts, "http")
					opts = append(opts, "--port")
					opts = append(opts, sj.Port)
					opts = append(opts, "--method")
					opts = append(opts, sj.Config.Scan_HTTP.Method)
					opts = append(opts, "--endpoint")
					opts = append(opts, sj.Config.Scan_HTTP.Endpoint)
					opts = append(opts, "--raw-headers")

					if sj.Config.Scan_HTTP.Useragent != "" {
						opts = append(opts, "--user-agent")
						opts = append(opts, sj.Config.Scan_HTTP.Useragent)

					}

					if sj.Config.Scan_HTTP.RetryHTTPS {
						opts = append(opts, "--retry-https")

					}

					if sj.Config.Scan_HTTP.HTTPS {
						opts = append(opts, "--use-https")
					}

					if sj.Config.Scan_HTTP.FailHTTPtoHTTPs {
						opts = append(opts, "--fail-http-to-https")
					}

					var httpFlags zgrab2.ScanFlags
					_, _, httpFlags, err = zgrab2.ParseCommandLine(opts)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					httpModule := &http.Module{}
					httpScanner := httpModule.NewScanner()
					err := httpScanner.Init(httpFlags)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					status, results, _ := httpScanner.Scan(sj.ZTarget)

					t := time.Now()

					// Grab and format the ZGRAB2 responses
					resp := zgrab2.ScanResponse{Result: results, Protocol: httpScanner.Protocol(), Error: e, Timestamp: t.Format(time.RFC3339), Status: status}

					moduleResult[httpScanner.GetName()] = resp
					raw := zgrab2.BuildGrabFromInputResponse(&sj.ZTarget, moduleResult)
					finalresult, _ := zgrab2.EncodeGrab(raw, true)
					json.Unmarshal(finalresult, &response)
					response.Port = sj.Port

				}

				// Banner Scan
				if sj.Config.Scan_Banner.Enabled {

					//Build options from Config struct to create the ZGRAB2 flags object
					var opts []string
					opts = append(opts, "banner")
					opts = append(opts, "--port")
					opts = append(opts, sj.Port)
					if len(sj.Config.Scan_Banner.Probefile) > 0 {
						opts = append(opts, "--probe")
						opts = append(opts, sj.Config.Scan_Banner.Probefile)
					}

					opts = append(opts, "--hex")

					var bannerFlags zgrab2.ScanFlags
					_, _, bannerFlags, err = zgrab2.ParseCommandLine(opts)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					bannerModule := &banner.Module{}
					bannerScanner := bannerModule.NewScanner()
					err := bannerScanner.Init(bannerFlags)

					if err != nil {
						log.Warning(fmt.Sprintf("Scan|%s|Error|IP -> %s, PORT -> %s, MALWARE_FAMILY -> %s, LOG_ERROR -> %s\n", runGUID, sj.Target, sj.Port, sj.Config.Rule_Name, err))
					}

					status, results, _ := bannerScanner.Scan(sj.ZTarget)

					t := time.Now()

					// Grab and format the ZGRAB2 responses
					resp := zgrab2.ScanResponse{Result: results, Protocol: bannerScanner.Protocol(), Error: e, Timestamp: t.Format(time.RFC3339), Status: status}

					moduleResult[bannerScanner.GetName()] = resp
					raw := zgrab2.BuildGrabFromInputResponse(&sj.ZTarget, moduleResult)
					finalresult, _ := zgrab2.EncodeGrab(raw, true)
					json.Unmarshal(finalresult, &response)
					response.Port = sj.Port

				}

				// Saves db struct to output q for post processing
				outputQueue <- response
			}
			workerDone.Done()

		}(i)
	}

	// Add scan jobs to worker queue
	for _, scan := range scans {
		workerQueue <- scan
	}

	// Close workers and GO Routines
	close(workerQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()

	return outputQueue
}

func zgrab2_add_scan_data(outputQueue chan nowhere2hide.GeneralResponse, runGUID string) {

	log.Info(fmt.Sprintf("AddDB|%s|Info|Adding %d results to Database \n", runGUID, len(outputQueue)))

	var wg sync.WaitGroup

	// Define the number of goroutines (workers) to use
	numWorkers := 10

	// Spawn worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for response := range outputQueue {
				addDB(response, runGUID)
			}
		}()
	}

	// Wait for all workers to finish
	wg.Wait()
}

func addDB(response nowhere2hide.GeneralResponse, runGUID string) {
	// Part 3 Add to Postgres Database

	if response.Data.Banner.Status == "success" {

		//Attempt to convert banner hex code into readable text
		var banner_text string
		temp_text, err := hex.DecodeString(response.Data.Banner.Result.Banner)

		if err != nil {
			log.Info(fmt.Sprintf("AddDB|%s|Error|IP -> %s, PORT -> %s, ERROR -> %s", runGUID, response.IP, response.Port, err))
			banner_text = ""
		} else {
			banner_text = string(temp_text)
		}

		//Save results into a Postgres Banner struct to add to the Database
		var bannerDB nowhere2hide.DB_Banner
		bannerDB.Uid = runGUID
		bannerDB.Address = response.IP
		bannerDB.Port = response.Port
		bannerDB.Status = response.Data.Banner.Status
		bannerDB.Banner_Hex = response.Data.Banner.Result.Banner
		bannerDB.Banner_Text = banner_text
		bannerDB.Banner_Length = response.Data.Banner.Result.Length
		bannerDB.Timestamp = response.Data.Banner.Timestamp

		err = db.AddBanner(bannerDB)
		if err != nil {
			log.Info(fmt.Sprintf("AddDB|%s|Error|%s, DBB: %+v \n", runGUID, err, bannerDB))
		}
	}

	if response.Data.TLS.Status == "success" {

		//Save results into a Postgres tls struct to add to the Database
		var tlsDB nowhere2hide.DB_TLS
		tlsDB.Uid = runGUID
		tlsDB.Address = response.IP
		tlsDB.Port = response.Port
		tlsDB.Status = response.Data.TLS.Status
		tlsDB.Version = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Version
		tlsDB.Serial_Number = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Serial_Number

		if len(response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer.Common_Name) > 0 {
			tlsDB.Issuer_Common_Name = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer.Common_Name[0]
		}

		if len(response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer.Country) > 0 {
			tlsDB.Issuer_Country = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer.Country[0]
		}

		if len(response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer.Organization) > 0 {
			tlsDB.Issuer_Organization = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer.Organization[0]
		}

		tlsDB.Issuer_DN = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Issuer_DN

		if len(response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject.Common_Name) > 0 {
			tlsDB.Subject_Common_Name = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject.Common_Name[0]
		}
		if len(response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject.Country) > 0 {
			tlsDB.Subject_Country = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject.Country[0]
		}
		if len(response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject.Organization) > 0 {
			tlsDB.Subject_Organization = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject.Organization[0]
		}

		tlsDB.Subject_DN = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Subject_DN
		tlsDB.Fingerprint_Md5 = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Fingerprint_Md5
		tlsDB.Fingerprint_SHA1 = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Fingerprint_SHA1
		tlsDB.Fingerprint_SHA256 = response.Data.TLS.Result.Handshake_Log.Server_Certificates.Certificate.Parsed.Fingerprint_SHA256
		tlsDB.JA4X = "N/A"
		tlsDB.Timestamp = response.Data.TLS.Timestamp

		err := db.AddTLS(tlsDB)
		if err != nil {
			log.Info(fmt.Sprintf("AddDB|%s|Error|%s, DBB: %+v \n", runGUID, err, tlsDB))
		}
	}

	if response.Data.Jarm.Status == "success" {

		//Save results into a Postgres jarm struct to add to the Database
		var jarmDB nowhere2hide.DB_JARM
		jarmDB.Uid = runGUID
		jarmDB.Address = response.IP
		jarmDB.Port = response.Port
		jarmDB.Status = response.Data.Jarm.Status
		jarmDB.JARM_Fingerprint = response.Data.Jarm.Result.Fingerprint
		jarmDB.Timestamp = response.Data.Jarm.Timestamp

		err := db.AddJarm(jarmDB)
		if err != nil {
			log.Info(fmt.Sprintf("AddDB|%s|Error|%s, DBB: %+v \n", runGUID, err, jarmDB))
		}
	}

	if response.Data.HTTP.Status != "connection-timeout" {

		// Decode base64 headers
		headers, err := base64.StdEncoding.DecodeString(response.Data.HTTP.Result.Response.Headers_Raw)
		if err != nil {
			headers = []byte("ERROR PARSING HEADERS")
		}

		//Save results into a Postgres http struct to add to the Database
		var httpDB nowhere2hide.DB_HTTP
		httpDB.Uid = runGUID
		httpDB.Address = response.IP
		httpDB.Port = response.Port
		httpDB.Status = response.Data.HTTP.Status
		httpDB.Status_Line = response.Data.HTTP.Result.Response.Status_Line
		httpDB.Status_Code = response.Data.HTTP.Result.Response.Status_Code
		httpDB.Protocol_Name = response.Data.HTTP.Result.Response.Protocol.Name
		httpDB.Body = response.Data.HTTP.Result.Response.Body
		httpDB.Body_SHA256 = response.Data.HTTP.Result.Response.Body_Sha256
		httpDB.Headers = string(headers)
		httpDB.Timestamp = response.Data.HTTP.Timestamp

		err = db.AddHTTP(httpDB)
		if err != nil {
			log.Info(fmt.Sprintf("AddDB|%s|Error|%s, DBB: %+v \n", runGUID, err, httpDB))
		}
	}
}

func hunt_extract_certs(runGUID string) {
	var certs []nowhere2hide.HuntIO_Certs

	api_keys, err := utils.LoadAPI()
	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|HUNT|Error|%s", runGUID, err))
	}
	downloadURL := fmt.Sprintf("https://api.hunt.io/v1/feeds/certificates?token=%s", api_keys.HUNTIO)

	// Use http.Get to download the file
	log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Info|Downloading", runGUID))

	resp, err := gohttp.Get(downloadURL)
	if err != nil {
		log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Error|Error downloading Hunt IO Certs: %s\n", runGUID, err))
		return
	}
	defer resp.Body.Close()

	// Check for successful download
	if resp.StatusCode != gohttp.StatusOK {
		log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Error|Error downloading Hunt IO Certs: %d\n", runGUID, resp.StatusCode))
		return
	}

	// Read the entire response body into memory
	fileData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Error|Error reading Hunt IO Certs: %s\n", runGUID, err))
		return
	}

	// Create a new Reader from the in-memory buffer
	reader := io.Reader(bytes.NewReader(fileData))

	// Use a gzip.Reader to decompress the data
	greader, err := gzip.NewReader(reader)
	if err != nil {
		log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Error|Error decompressing Hunt IO Certs: %s\n", runGUID, err))
		return
	}
	defer greader.Close()

	log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Info|Parsing and Adding Certs", runGUID))
	count := 0
	scanner := bufio.NewScanner(greader)
	for scanner.Scan() {
		var temp nowhere2hide.HuntIO_Certs
		count = count + 1
		line := scanner.Bytes()
		json.Unmarshal(line, &temp)
		certs = append(certs, temp)

		//err := hunt_add_cert(temp, runGUID)
		//if err != nil {
		//	log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Error|Error adding Hunt IO Certs to DB: %s\n", runGUID, err))
		//}
	}
	log.Info(fmt.Sprintf("Scan|%s|hunt_cert|info|Extracted %d certs\n", runGUID, len(certs)))

	var wg sync.WaitGroup
	numWorkers := 10

	recordChan := make(chan nowhere2hide.HuntIO_Certs, len(certs))

	for _, record := range certs {
		recordChan <- record
	}
	close(recordChan)

	// Spawn worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for response := range recordChan {
				// Insert record into the database
				err := hunt_add_cert(response, runGUID)
				if err != nil {
					log.Info(fmt.Sprintf("Scan|%s|hunt_cert|Error|Error loading cert into DB: %s\n", runGUID, err))
				}
			}
		}()
	}

	// Wait for all workers to finish
	wg.Wait()
}

func hunt_add_cert(response nowhere2hide.HuntIO_Certs, runGUID string) error {

	var tlsDB nowhere2hide.DB_TLS
	tlsDB.Uid = runGUID

	if len(response.Scan_Endpoints) > 0 {
		temp := response.Scan_Endpoints[0]
		ip_port := strings.Split(temp, ":")
		tlsDB.Address = ip_port[0]
		tlsDB.Port = ip_port[1]
	} else {
		tlsDB.Address = "Not Provided by Hunt IO"
		tlsDB.Port = "Not Provided by Hunt IO"
	}

	tlsDB.Status = "N/A"
	tlsDB.Version = response.Version
	tlsDB.Serial_Number = response.Serial
	tlsDB.Issuer_Common_Name = response.IssuerCommonName

	if len(response.IssuerCountry) > 0 {
		tlsDB.Issuer_Country = response.IssuerCountry[0]
	}

	if len(response.IssuerOrganization) > 0 {
		tlsDB.Issuer_Organization = response.IssuerOrganization[0]
	}

	tlsDB.Issuer_DN = "N/A"
	tlsDB.Subject_Common_Name = response.SubjectCommonName

	if len(response.SubjectCountry) > 0 {
		tlsDB.Subject_Country = response.SubjectCountry[0]
	}

	if len(response.SubjectOrganization) > 0 {
		tlsDB.Subject_Organization = response.SubjectOrganization[0]
	}

	tlsDB.Subject_DN = "N/A"
	tlsDB.Fingerprint_Md5 = response.HashMd5
	tlsDB.Fingerprint_SHA1 = response.HashSha1
	tlsDB.Fingerprint_SHA256 = response.HashSha256
	tlsDB.JA4X = response.JA4X
	tlsDB.Timestamp = response.SeenLast

	err := db.AddTLS(tlsDB)
	if err != nil {
		return err
	}
	return nil
}
