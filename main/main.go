package main

import (
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"nowhere2hide"
	"nowhere2hide/db"
	"nowhere2hide/utils"
	"path/filepath"
	"plugin"
	"strings"

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

func getTargetSources() []string {
	var targets []string

	err := filepath.Walk("plugin/targets/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.Contains(info.Name(), ".so") {

			p, err := plugin.Open(path)
			if err != nil {
				return err
			}

			collectInstance, err := p.Lookup("Collect")
			if err != nil {
				return err
			}

			collectFunc := collectInstance.(nowhere2hide.Collection)
			targets = append(targets, fmt.Sprintf("%s:%s", collectFunc.Get_Name(), fmt.Sprintf("%t", collectFunc.Get_QueryBox())))

		}
		return nil

	})
	if err != nil {
		log.Info(fmt.Sprintf("Main|Error|Error with loading target -> %s", err))
	}
	return targets

}

func getCustomDetection() []string {
	var detections []string

	err := filepath.Walk("plugin/c2/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.Contains(info.Name(), ".so") {

			p, err := plugin.Open(path)
			if err != nil {
				return err
			}

			detectInstance, err := p.Lookup("Detect")
			if err != nil {
				return err
			}

			detectFunc := detectInstance.(nowhere2hide.Detectors)
			detections = append(detections, detectFunc.Get_Name())

		}
		return nil

	})
	if err != nil {
		log.Info(fmt.Sprintf("Main|Error|Error with loading target -> %s", err))
	}
	return detections

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

	// API Handelers
	r.HandleFunc("/Auth", authHandler).Methods("POST")
	r.HandleFunc("/C2List", getC2ListHandler).Methods("GET")
	r.Handle("/Retro", authMiddleware(http.HandlerFunc(retroHandler))).Methods("POST")
	r.Handle("/HuntIOCert", authMiddleware(http.HandlerFunc(huntIOCertsHandler))).Methods("POST")
	r.HandleFunc("/RecordCountQ", getRecordCountQHandler).Methods("POST")
	r.HandleFunc("/Query", getQueryHandler).Methods("POST")
	r.HandleFunc("/C2S", getC2Handler).Methods("GET")
	r.HandleFunc("/C2query", getC2QueryHandler).Methods("POST")
	r.HandleFunc("/Sigs", getSigsHandler).Methods("GET")
	r.Handle("/RunScan", authMiddleware(http.HandlerFunc(runScanHandler))).Methods("POST")
	r.HandleFunc("/Jobs", getJobsHandler).Methods("GET")
	r.Handle("/AddSig", authMiddleware(http.HandlerFunc(addSigHandler))).Methods("POST")
	r.HandleFunc("/GetSig", getSigHandler).Methods("POST")
	r.Handle("/ClearDB", authMiddleware(http.HandlerFunc(clearDBQueryHandler))).Methods("POST")

	// UI / HTML Template Handlers
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/c2", c2Handler).Methods("GET")
	r.HandleFunc("/runscan", runscanHandler).Methods("GET")
	r.HandleFunc("/querydb", queryHandler).Methods("GET")
	r.HandleFunc("/queryuid", queryUIDHandler).Methods("GET")
	r.HandleFunc("/status", statusHandler).Methods("GET")
	r.HandleFunc("/readme", readmeHandler).Methods("GET")
	r.HandleFunc("/utilities", utilitiesHandler).Methods("GET")
	r.HandleFunc("/cleardb", clearHandler).Methods("GET")
	r.HandleFunc("/newsig", newsigHandler).Methods("GET")
	r.HandleFunc("/viewsigs", viewsigsHandler).Methods("GET")
	r.HandleFunc("/editsig", editsigHandler).Methods("GET")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))
	http.Handle("/", r)

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
