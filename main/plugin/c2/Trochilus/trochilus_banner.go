package main

import (
	"bytes"
	"nowhere2hide"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Create a new instance of the logger.
var log = logrus.New()

type TROCHILUS struct{}

func (m TROCHILUS) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/c2_modules.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info("Detect|modules|Error|Error Failed to log to file, using default stderr")
	}
}

func (m TROCHILUS) Get_Name() string {
	return "trochilus_banner"

}

func (m TROCHILUS) Get_Payload_Type() string {

	//return "http"
	return "banner"

}

// Main function to analyze data. Required arguments c2_detector struct.
func (m TROCHILUS) Process(data nowhere2hide.C2Detector) nowhere2hide.C2DetectorResponse {

	var results nowhere2hide.C2DetectorResponse
	results.Valid = false

	banner := data.Banner_Payload

	verification := []byte{0xbf, 0xbf, 0xaf, 0xaf}
	if len(banner) > 16 {
		if banner[5] != 0x7e {
			if bytes.Equal(banner[:4], verification) {
				res := decode(banner[8:])
				if strings.Contains(res, "__msgid") {
					if !strings.Contains(res, "clientid") {
						results.Valid = true
						results.Additional = res
					}
				}
			}

		}
	}
	return results
}

var Detect TROCHILUS

func decode(banner []byte) string {

	first := 7
	second := 2

	var decoded []byte
	var decoded_string string

	for _, b := range banner {
		xor_key := (first + second) % 0xff
		second = first
		first = xor_key
		decoded = append(decoded, (b ^ byte(xor_key)))
	}

	if len(decoded) > 0 {

		return (string(decoded))

	}
	return decoded_string

}
