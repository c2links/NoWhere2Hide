package nowhere2hide

type C2Detector struct {
	Banner_Payload []byte
	HTTP_Payload   []byte
}

type C2DetectorResponse struct {
	Valid      bool
	Version    string
	Additional string
}

type Detectors interface {
	// Logging Function
	Init()

	Get_Name() string

	Get_Payload_Type() string

	// Main function to analyze data. Required arguments c2_detector struct.
	Process(C2Detector) C2DetectorResponse
}
