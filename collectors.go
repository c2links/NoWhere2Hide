package nowhere2hide

type Collection interface {
	// Logging Function
	Init()

	// Main collector function. Required arguments are the C2_config and the runGUID.
	Get_Name() string

	Get_QueryBox() bool

	// Main collector function. Required arguments are the C2_config and the runGUID.
	Run(c2_config *C2_Config, query string, runGUID string) []*Scan

	// Most collectors will also need a query. however this is not a required field.
	Get_Targets(query string, runGUID string) []Target
}
