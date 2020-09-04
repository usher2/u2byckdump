package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	xml01 string = `<?xml version="1.0" encoding="utf-8"?>
                <resources date="2020-09-03 06:32:22">
                        <resource id="1">
                                <ip>10.1.1.1</ip>
                                <dns>example.tld</dns>
                                <url>http://www.example.tld</url>
                                <dateoff>2011-01-01</dateoff>
                                <info>Тест 1</info>
                        </resource>
                        <resource id="2">
                                <ip>-</ip>
                                <dns>-</dns>
                                <url>http://test.tld</url>
                                <dateoff>2018-04-16</dateoff>
                                <info>Тест 2</info>
                        </resource>
                        <resource id="3">
                                <ip>10.3.3.3</ip>
                                <dns>testik.tld</dns>
                                <url>-</url>
                                <dateoff>2020-07-16</dateoff>
                                <info>Тест 3</info>
                        </resource>
                </resources>`

	xml02 string = `<?xml version="1.0" encoding="utf-8"?>
                <resources date="2020-09-03 12:32:22">
                        <resource id="1">
                                <ip>10.1.1.1</ip>
                                <dns>example.tld</dns>
                                <url>http://www.example.tld</url>
                                <dateoff>2011-01-01</dateoff>
                                <info>Тест 1</info>
                        </resource>
                        <resource id="3">
                                <ip>-</ip>
                                <dns>testik.tld</dns>
                                <url>-</url>
                                <dateoff>2020-07-16</dateoff>
                                <info>Тест 3</info>
                        </resource>
                </resources>`
)

func Test_Parse(t *testing.T) {
	logInit(os.Stderr, os.Stdout, os.Stderr, os.Stderr)
	dumpFile := strings.NewReader(xml01)
	err := Parse(dumpFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	if Stats.MaxArrayIntSet != 1 ||
		Stats.Cnt != 3 ||
		Stats.CntAdd != 3 ||
		Stats.CntUpdate != 0 ||
		Stats.CntRemove != 0 {
		t.Errorf("Stat error")
	}
	if len(DumpSnap.ip) != 2 ||
		len(DumpSnap.url) != 2 ||
		len(DumpSnap.domain) != 2 {
		t.Errorf("Count error")
	}
	if len(DumpSnap.Content) != 3 ||
		len(DumpSnap.Content) != Stats.Cnt {
		t.Errorf("DumpSnap integrity error")
	}

	fmt.Println()
	dumpFile = strings.NewReader(xml02)
	err = Parse(dumpFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Printf("IP4:\n%v\n", DumpSnap.ip)
	for k, _ := range DumpSnap.Content {
		fmt.Printf("%d ", k)
	}
	fmt.Println()
}
