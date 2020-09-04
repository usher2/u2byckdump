package main

import (
	"sync"
)

type (
	Nothing        struct{}
	IntSet         map[int32]Nothing
	TMinContentMap map[int32]*TMinContent
)

var NothingV = Nothing{}

type Stat struct {
	Cnt            int
	CntAdd         int
	CntUpdate      int
	CntRemove      int
	MaxArrayIntSet int
	MaxContentSize int
}

var Stats Stat

type TDump struct {
	sync.RWMutex
	utime   int64
	ip      Ip4Set
	url     StringIntSet
	domain  StringIntSet
	Content TMinContentMap
}

func NewTDump() *TDump {
	return &TDump{
		utime:   0,
		ip:      make(Ip4Set),
		url:     make(StringIntSet),
		domain:  make(StringIntSet),
		Content: make(TMinContentMap),
	}
}

func (t *TDump) AddIp(ip uint32, id int32) {
	t.ip.Add(ip, id)
}

func (t *TDump) DeleteIp(ip uint32, id int32) {
	t.ip.Delete(ip, id)
}

func (t *TDump) AddUrl(i string, id int32) {
	t.url.Add(i, id)
}
func (t *TDump) DeleteUrl(i string, id int32) {
	t.url.Delete(i, id)
}

func (t *TDump) AddDomain(i string, id int32) {
	t.domain.Add(i, id)
}
func (t *TDump) DeleteDomain(i string, id int32) {
	t.domain.Delete(i, id)
}

var DumpSnap = NewTDump()

type TReg struct {
	UpdateTime int64
}

func Parse2(UpdateTime int64) {
	DumpSnap.Lock()
	for _, v := range DumpSnap.Content {
		v.RegistryUpdateTime = UpdateTime
	}
	DumpSnap.utime = UpdateTime
	DumpSnap.Unlock()
}
