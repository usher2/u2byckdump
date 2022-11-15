package main

import "time"

const cParseResourcesDate = "2006-01-02 15:04:05"
const cParseDateOff = "2006-01-02 15:04:05"

func parseTimeMSK(tpl string, s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(tpl, s)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err.Error(), s)
		return 0
	}
	return t.Unix() - 3600*3
}
