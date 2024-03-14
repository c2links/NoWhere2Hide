package nowhere2hide

import (
	"github.com/zmap/zgrab2"
)

/*
This contains the structs needed for target and scanning components of NoWhere2Hide
*/

type Masscan_Port struct {
	Port   int
	Proto  string
	Status string
	Reason string
	TTL    int
}

type MassScan_Results struct {
	IP    string `json:'ip'`
	Ports []Masscan_Port
}

type Target struct {
	Target      string
	Target_Type string
	Port        int
}

type C2Results struct {
	UID                string
	Address            string
	Port               string
	Malware_Family     string
	Rule_Name          string
	Description        string
	Classification     string
	Version            string
	Additional_Details string
	First_Seen         string
	Last_Seen          string
}

type Scan struct {
	Port         string
	Target       string
	ZTarget      zgrab2.ScanTarget
	Config       *C2_Config
	Type         string
	TargetSource string
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
