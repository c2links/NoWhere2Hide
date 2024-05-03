package main

import (
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"nowhere2hide/db"
	"nowhere2hide/utils"

	"os"

	"github.com/beevik/guid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	// Import the `pq` package with a preceding underscore since it is imported as a side
	// effect. The `pq` package is a GO Postgres driver for the `database/sql` package.
	_ "github.com/lib/pq"
)

type Arguments struct {
	PORT       string
	Signatures string
}

var runArgs Arguments

var log = logrus.New()

func init() {
	// Create a new instance of the logger.

	// Only log the debug severity or above.

	log.SetLevel(logrus.DebugLevel)

}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		err := r.ParseForm()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Info(fmt.Sprintf("UI Error -> %s", err))
		}

		for element, value := range r.Form {
			if element == "c2-auth" {
				if value[0] == "" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				_, exists := store.CheckTokenExists(value[0])
				if exists {
					next.ServeHTTP(w, r)
				} else {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return

				}
			}
		}

	})
}

func newRouter() *mux.Router {

	r := mux.NewRouter()

	/*
		Below is the documentation on the how the UI works and a breakdown of each API call.

		The handlers handle every aspect of the UI and either use the "store.go" to pull data from the Postgres database,
		or call functions from the "run.go", which is connects the UI to the NoWhere2Hide scanning engine.


		################################################
		# API:/C2List
		# Handler: getC2Handler
		# Store: GetC2List() ([]*C2_Count, error)
		# Postgres Query:
		# Engine: None
		# UI Method: GET
		# UI Parameters(Name|Type|Description): None
		# UI Return: json.Marshal(C2List)
		# Description: Returns counts by malware family of C2 Database.
		################################################

		################################################
		# API:/Retro
		# Handler: retroHandler
		# Store: None
		# Engine: RunRetro() string
		# UI Method: GET
		# UI Parameters(Name|Type|Description): None
		# UI Return: string Message
		# Description: Runs the RunRetro function from main.go that will run all the detections in the configs
		################################################

		################################################
		# API: /RecordCount
		# Handler: getRecordCountHandler / GetRecordCount
		# Store: None
		# Engine: RunRetro() string
		# UI Method: POST
		# UI Parameters(Name|Type|Description): "table|string|Name of table to pull record count from"
		# UI Return: int RecordCount
		# Description: Gets the number of records in a the specified table
		################################################

		################################################
		# API: /RecordCountQ:
		# Handler / Store: getRecordCountQHandler / GetRecordCountQ
		# Method: POST
		# Parameters(Name|Type|Description): "table|string|Name of table to pull record count from", "query|string|query to use at as a search"
		# Return Value: int RecordCount
		# Description: Gets the number of records in a the specified table using the supplied search term
		################################################

		################################################
		# API: /C2s
		# Handler / Store: getC2Handler / GetC2
		# Method: GET
		# Parameters(Name|Type|Description):
		# Return Value: []*C2_Record
		# Description: Returns the C2's from the C2 database. Used to display the results in the UI.
		################################################

		################################################
		# API: /C2Query
		# Handler / Store: getC2QueryHandler / GetC2Query
		# Method: POST
		# Parameters(Name|Type|Description): "malware|string|Malware family to filter the C2's by"
		# Return Value: []*C2_Record
		# Description: Returns the C2's from the C2 database based on the supplied query. Used to display the results in the UI.
		################################################

		################################################
		# API: /Ban
		# Handler / Store: getBannerHandler / GetBanner
		# Method: POST
		# Parameters(Name|Type|Description): "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*Banner_Record
		# Description: Returns the paged banner scan data from the Banner database. Used to display the results in the UI.
		################################################

		################################################
		# API: /BanQuery
		# Handler / Store: getBannerQueryHandler / GetBannerQuery
		# Method: POST
		# Parameters(Name|Type|Description): "pg|string|the query to filter banner table on", "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*Banner_Record
		# Description: Returns the paged banner scan (filtered by the supplied query) data from the banner database. Used to display the results in the UI.
		################################################

		################################################
		# API: /TLS
		# Handler / Store: getTLSHandler / GetTLS
		# Method: POST
		# Parameters(Name|Type|Description): "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*TLS_Record
		# Description: Returns the paged tls scan data from the tls database. Used to display the results in the UI.
		################################################

		################################################
		# API: /TLSQuery
		# Handler / Store: getTLSQueryHandler / GetTLSQuery
		# Method: POST
		# Parameters(Name|Type|Description): "pg|string|the query to filter tls table on", "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*TLS_Record
		# Description: Returns the paged tls scan (filtered by the supplied query) data from the tls database. Used to display the results in the UI.
		################################################

		################################################
		# API: /HTTP
		# Handler / Store: getHTTPHandler / GetHTTP
		# Method: POST
		# Parameters(Name|Type|Description): "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*HTTP_Record
		# Description: Returns the paged http scan data from the http database. Used to display the results in the UI.
		################################################

		################################################
		# API: /HTTPQuery
		# Handler / Store: getHTTPQueryHandler / GetHTTPQuery
		# Method: POST
		# Parameters(Name|Type|Description): "pg|string|the query to filter http table on", "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*HTTP_Record
		# Description: Returns the paged http scan (filtered by the supplied query) data from the http database. Used to display the results in the UI.
		################################################

		################################################
		# API: /Jarm
		# Handler / Store: getJarmHandler / GetJarm
		# Method: POST
		# Parameters(Name|Type|Description): "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*JARM_Record
		# Description: Returns the paged jarm scan data from the jarm database. Used to display the results in the UI.
		################################################

		################################################
		# API: /JarmQuery
		# Handler / Store: getJarmQueryHandler / GetJarmQuery
		# Method: POST
		# Parameters(Name|Type|Description): "pg|string|the query to filter jarm table on", "limit|string|The amount of records to return", "limit|string|he offset / page to return results from"
		# Return Value: []*JARM_Record
		# Description: Returns the paged jarm scan (filtered by the supplied query) data from the jarm database. Used to display the results in the UI.
		################################################

		################################################
		# API: /Sigs
		# Handler / Store: getSigsHandler
		# Method: GET
		# Parameters(Name|Type|Description):
		# Return Value: []byte
		# Description: Returns a list containing the names of the current signatures. Used to populate the UI when the user is running a scan
		################################################

		################################################
		# API: /RunScan
		# Handler / Store: runScanHandler
		# Method: POST
		# Parameters(Name|Type|Description): []string (signatures to run)
		# Return Value: None
		# Description: Runs the scans that were selected in the UI
		################################################

		################################################
		# API: /Jobs
		# Handler / Store: getJobsHandler / GetJobs
		# Method: GET
		# Parameters(Name|Type|Description):
		# Return Value: []*Job_Status
		# Description: Returns the status of the last 20 jobs submitted
		################################################

		################################################
		# API: /AddSig
		# Handler / Store: addSigHandler
		# Method: POST
		# Parameters(Name|Type|Description):
		# Return Value: []byte
		# Description: Creates a new detection signature based on the values provided in the UI form		################################################
		################################################


		/AddSig POST ([]FormData) - >
		/GetSig GET -> Retrieves a detection signature for viewing or editing


	*/

	r.HandleFunc("/Auth", authHandler).Methods("POST")

	r.HandleFunc("/C2List", getC2ListHandler).Methods("GET")
	r.Handle("/Retro", authMiddleware(http.HandlerFunc(retroHandler))).Methods("POST")
	r.Handle("/HuntIOCert", authMiddleware(http.HandlerFunc(huntIOCertsHandler))).Methods("POST")

	r.HandleFunc("/RecordCount", getRecordCountHandler).Methods("POST")
	r.HandleFunc("/RecordCountQ", getRecordCountQHandler).Methods("POST")

	r.HandleFunc("/C2S", getC2Handler).Methods("GET")
	r.HandleFunc("/C2query", getC2QueryHandler).Methods("POST")

	r.HandleFunc("/Ban", getBannerHandler).Methods("POST")
	r.HandleFunc("/Banquery", getBannerQueryHandler).Methods("POST")

	r.HandleFunc("/Jarm", getJarmHandler).Methods("POST")
	r.HandleFunc("/Jarmquery", getJarmQueryHandler).Methods("POST")

	r.HandleFunc("/HTTP", getHTTPHandler).Methods("POST")
	r.HandleFunc("/HTTPquery", getHTTPQueryHandler).Methods("POST")

	r.HandleFunc("/TLS", getTLSHandler).Methods("POST")
	r.HandleFunc("/TLSquery", getTLSQueryHandler).Methods("POST")

	r.HandleFunc("/Sigs", getSigsHandler).Methods("GET")

	r.Handle("/RunScan", authMiddleware(http.HandlerFunc(runScanHandler))).Methods("POST")
	r.HandleFunc("/Jobs", getJobsHandler).Methods("GET")

	r.Handle("/AddSig", authMiddleware(http.HandlerFunc(addSigHandler))).Methods("POST")
	r.HandleFunc("/GetSig", getSigHandler).Methods("POST")

	r.Handle("/ClearDB", authMiddleware(http.HandlerFunc(clearDBQueryHandler))).Methods("POST")

	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("static/"))))

	return r
}

func main() {

	var port string
	var signatures string

	flag.StringVar(&port, "p", "6332", "Port that server runs on")
	flag.StringVar(&signatures, "signatures", "../signatures/c2configs", "Path where signatures are located")

	flag.Parse()

	runArgs.PORT = port
	runArgs.Signatures = signatures

	file, err := os.OpenFile("../logs/main.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("Main|Error|Failed to log to file, using default stderr")
	}

	mainGUID := guid.New()

	// Create needed databases
	success := db.InitDB()

	if !success {
		log.Info(fmt.Sprintf("Main|%s|Error|Error creating databases", mainGUID))
		return
	}

	// Setup connection to our postgresql database
	connString := utils.GetConnectionString()
	db, err := sql.Open("postgres", connString)

	if err != nil {
		log.Info(fmt.Sprintf("Main|%s|Error|Error opening databases %s", mainGUID, err))
		return
	}

	// Check whether we can access the database by pinging it
	err = db.Ping()

	if err != nil {
		log.Info(fmt.Sprintf("Main|%s|Error|Error opening databases %s", mainGUID, err))
		return
	}

	// Place our opened database into a `dbstruct` and assign it to `store` variable.
	// The `store` variable implements a `Store` interface. The `store` variable was
	// declared globally in `store.go` file.

	store = &dbStore{db: db}

	if !store.CheckAdminExists() {

		token := guid.New().String()
		store.AddAdminToken(token)

	}

	err, token := store.GetAdminToken()
	if err != nil {
		fmt.Println("error getting token")
	}

	fmt.Printf("Admin Token for Authentication is: %s", token)
	// Only write to the auth log if this environment variable is set
	_, ok := os.LookupEnv("NW2H_AUTH")
	if ok {
		afile, err := os.OpenFile("../logs/auth.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("Failed to open auth.log: %v", err)
		} else {
			afile.WriteString(fmt.Sprintf("%s\n", token))
			afile.Close()
		}
	}

	// Create router
	r := newRouter()

	// Listen to the port.
	log.Info(fmt.Sprintf("Main|%s|Info|Server started http://localhost:6332", mainGUID))
	http.ListenAndServe(fmt.Sprintf(":%s", runArgs.PORT), r)

	// Port
	// Config

}
