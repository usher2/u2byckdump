package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"hash"
	"hash/fnv"
	"io"
	"strconv"

	pb "github.com/usher2/u2byckdump/msg"
)

const (
	elementRegister          = "resources"
	elementContent           = "resource"
	elementIncludeTimeLegacy = "dateoff"
	elementIncludeTime       = "date_off"
	elementDecisionLegacy    = "info"
	elementDecision          = "decision"
	elementDecisionInfo      = "decision_info"
	elementUrl               = "url"
	elementDomain            = "dns"
	elementIp                = "ip"
)

var __h64 hash.Hash64

func UnmarshalContent(b []byte, v *TContent) error {
	buf := bytes.NewReader(b)
	decoder := xml.NewDecoder(buf)
	for {
		t, err := decoder.Token()
		if t == nil {
			if err != io.EOF {
				return err
			}
			break
		}
		switch element := t.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case elementContent:
				if err := parseContentElement(element, v); err != nil {
					return err
				}
			case elementIncludeTime, elementIncludeTimeLegacy:
				var t string
				if err := decoder.DecodeElement(&t, &element); err != nil {
					return err
				}
				v.IncludeTime = parseTimeMSK(cParseDateOff, t) + 3600*12 // dirty hack for noon
			case elementDecision, elementDecisionLegacy:
				if err := decoder.DecodeElement(&v.Decision, &element); err != nil {
					return err
				}
			case elementDecisionInfo:
				if err := decoder.DecodeElement(&v.DecisionInfo, &element); err != nil {
					return err
				}
			case elementUrl:
				u := TXMLUrl{}
				if err := decoder.DecodeElement(&u, &element); err != nil {
					return err
				}
				if u.Url != "-" {
					v.Url = append(v.Url, TUrl{Url: u.Url})
				}
			case elementDomain:
				d := TXMLDomain{}
				if err := decoder.DecodeElement(&d, &element); err != nil {
					return err
				}
				if d.Domain != "-" {
					v.Domain = append(v.Domain, TDomain{Domain: d.Domain})
				}
			case elementIp:
				ip := TXMLIp{}
				if err := decoder.DecodeElement(&ip, &element); err != nil {
					return err
				}
				if ip.Ip != "-" {
					v.Ip4 = append(v.Ip4, TIp4{Ip4: parseIp4(ip.Ip)})
				}
			}
		}
	}
	return nil
}

func parseContentElement(element xml.StartElement, v *TContent) error {
	for _, attr := range element.Attr {
		switch attr.Name.Local {
		case "id":
			if err := parseInt32(&v.Id, attr.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

func Parse(dumpFile io.Reader) error {
	var (
		err                            error
		r                              TReg
		buffer                         bytes.Buffer
		bufferOffset, offsetCorrection int64
	)
	__h64 = fnv.New64a()
	Stats = Stat{}
	decoder := xml.NewDecoder(io.TeeReader(dumpFile, &buffer))
	offsetCorrection = decoder.InputOffset()
	SPass := make(IntSet, len(DumpSnap.Content)+1000)
	for {
		tokenStartOffset := decoder.InputOffset() - offsetCorrection
		t, err := decoder.Token()
		if t == nil {
			if err != io.EOF {
				return err
			}
			break
		}
		switch _e := t.(type) {
		case xml.StartElement:
			switch _e.Name.Local {
			case elementRegister:
				handleRegister(_e, &r)
			case elementContent:
				// id := getContentId(_e)
				// parse <resource>...</resource> only if need
				decoder.Skip()
				dif := tokenStartOffset - bufferOffset
				buffer.Next(int(dif))
				bufferOffset += dif
				tokenStartOffset = decoder.InputOffset() - offsetCorrection
				// create hash of <resource>...</resource> for comp
				tempBuf := buffer.Next(int(tokenStartOffset - bufferOffset))
				if Stats.MaxContentSize < len(tempBuf) {
					Stats.MaxContentSize = len(tempBuf)
				}
				__h64.Reset()
				__h64.Write(tempBuf)
				u2Hash := __h64.Sum64()
				bufferOffset = tokenStartOffset
				v := TContent{}
				// create or update
				DumpSnap.Lock()
				v0, exists := DumpSnap.Content[u2Hash]
				if !exists {
					err := UnmarshalContent(tempBuf, &v)
					if err != nil {
						Error.Printf("Decode Error: %s\n", err.Error())
					} else {
						v.Add(u2Hash, r.UpdateTime)
						Stats.CntAdd++
					}
					SPass[u2Hash] = NothingV
				} else if v0.U2Hash != u2Hash {
					err := UnmarshalContent(tempBuf, &v)
					if err != nil {
						Error.Printf("Decode Error: %s\n", err.Error())
					} else {
						v.Update(u2Hash, v0, r.UpdateTime)
						Stats.CntUpdate++
					}
					SPass[u2Hash] = NothingV
				} else {
					DumpSnap.Content[u2Hash].RegistryUpdateTime = r.UpdateTime
					SPass[v0.U2Hash] = NothingV
					//v = nil
				}
				DumpSnap.Unlock()
				Stats.Cnt++
			}
		default:
			//fmt.printf("%v\n", _e)
		}
		dif := tokenStartOffset - bufferOffset
		buffer.Next(int(dif))
		bufferOffset += dif
	}
	// remove operations
	DumpSnap.Lock()
	for id, o2 := range DumpSnap.Content {
		if _, ok := SPass[id]; !ok {
			for _, v := range o2.Ip4 {
				DumpSnap.DeleteIp(v.Ip4, o2.U2Hash)
			}
			for _, v := range o2.Url {
				url, domain := NormalizeUrl(v.Url)
				DumpSnap.DeleteUrl(url, o2.U2Hash)
				if len(o2.Domain) == 0 {
					DumpSnap.DeleteDomain(domain, o2.U2Hash)
				}
			}
			for _, v := range o2.Domain {
				DumpSnap.DeleteDomain(NormalizeDomain(v.Domain), o2.U2Hash)
			}
			delete(DumpSnap.Content, id)
			Stats.CntRemove++
		}
	}
	DumpSnap.utime = r.UpdateTime
	Stats.MaxArrayIntSet = 0
	for _, a := range DumpSnap.ip {
		if Stats.MaxArrayIntSet < len(a) {
			Stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.url {
		if Stats.MaxArrayIntSet < len(a) {
			Stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.domain {
		if Stats.MaxArrayIntSet < len(a) {
			Stats.MaxArrayIntSet = len(a)
		}
	}
	DumpSnap.Unlock()
	Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", Stats.Cnt, Stats.CntAdd, Stats.CntUpdate, Stats.CntRemove)
	Info.Printf("  IP: %d Domains: %d URSs: %d\n",
		len(DumpSnap.ip), len(DumpSnap.domain), len(DumpSnap.url))
	Info.Printf("Biggest array: %d\n", Stats.MaxArrayIntSet)
	Info.Printf("Biggest resource: %d\n", Stats.MaxContentSize)
	return err
}

func (v *TContent) Marshal() []byte {
	b, err := json.Marshal(v)
	if err != nil {
		Error.Printf("Error encoding: %s\n", err.Error())
	}
	return b
}

func (v *TContent) constructBlockType() int32 {
	if len(v.Url) > 0 {
		if v.HttpsBlock == 0 {
			return TBLOCK_URL
		} else {
			return TBLOCK_HTTPS
		}
	} else if len(v.Domain) > 0 {
		return TBLOCK_DOMAIN
	} else if len(v.Ip4) > 0 {
		return TBLOCK_IP
	} else {
		return TBLOCK_UNKNOWN
	}
}

func (v *TContent) Update(u2Hash uint64, o *TMinContent, updateTime int64) {
	pack := v.Marshal()
	v1 := newMinContent(v.Id, u2Hash, updateTime, pack)
	DumpSnap.Content[u2Hash] = v1
	v1.handleUpdateIp(v, o)
	v1.handleUpdateUrl(v, o)
	v1.handleUpdateDomain(v, o)
	v1.BlockType = v.constructBlockType()
}

func (v *TContent) Add(u2Hash uint64, updateTime int64) {
	pack := v.Marshal()
	v1 := newMinContent(v.Id, u2Hash, updateTime, pack)
	DumpSnap.Content[u2Hash] = v1
	v1.handleAddIp(v)
	v1.handleAddUrl(v)
	v1.handleAddDomain(v)
	v1.BlockType = v.constructBlockType()
}

func (v *TMinContent) handleAddIp(v0 *TContent) {
	if len(v0.Ip4) > 0 {
		v.Ip4 = v0.Ip4
		for i := range v.Ip4 {
			DumpSnap.AddIp(v.Ip4[i].Ip4, v.U2Hash)
		}
	}
}

func (v *TMinContent) handleUpdateIp(v0 *TContent, o *TMinContent) {
	ipSet := make(map[uint32]Nothing, len(v.Ip4))
	if len(v0.Ip4) > 0 {
		v.Ip4 = v0.Ip4
		for i := range v.Ip4 {
			DumpSnap.AddIp(v.Ip4[i].Ip4, v.U2Hash)
			ipSet[v.Ip4[i].Ip4] = NothingV
		}
	}
	for i := range o.Ip4 {
		ip := o.Ip4[i].Ip4
		if _, ok := ipSet[ip]; !ok {
			DumpSnap.DeleteIp(ip, o.U2Hash)
		}
	}
}

func (v *TMinContent) handleAddDomain(v0 *TContent) {
	if len(v0.Domain) > 0 {
		v.Domain = v0.Domain
		for _, value := range v.Domain {
			domain := NormalizeDomain(value.Domain)
			DumpSnap.AddDomain(domain, v.U2Hash)
		}
	}
}

func (v *TMinContent) handleUpdateDomain(v0 *TContent, o *TMinContent) {
	domainSet := NewStringSet(len(v.Domain))
	if len(v0.Domain) > 0 {
		v.Domain = v0.Domain
		for _, value := range v.Domain {
			domain := NormalizeDomain(value.Domain)
			DumpSnap.AddDomain(domain, v.U2Hash)
			domainSet[domain] = NothingV
		}
	}
	for _, value := range o.Domain {
		domain := NormalizeDomain(value.Domain)
		if _, ok := domainSet[domain]; !ok {
			DumpSnap.DeleteDomain(domain, o.U2Hash)
		}
	}
}

func (v *TMinContent) handleAddUrl(v0 *TContent) {
	if len(v0.Url) > 0 {
		v.Url = v0.Url
		for _, value := range v.Url {
			url, domain := NormalizeUrl(value.Url)
			DumpSnap.AddUrl(url, v.U2Hash)
			if url[:8] == "https://" {
				v0.HttpsBlock += 1
			}
			if len(v0.Domain) == 0 {
				DumpSnap.AddDomain(domain, v.U2Hash)
			}
		}
	}
}

func (v *TMinContent) handleUpdateUrl(v0 *TContent, o *TMinContent) {
	urlSet := NewStringSet(len(v0.Url))
	domainSet := NewStringSet(len(v0.Url))
	if len(v0.Url) > 0 {
		v.Url = v0.Url
		for _, value := range v.Url {
			url, domain := NormalizeUrl(value.Url)
			DumpSnap.AddUrl(url, v.U2Hash)
			if url[:8] == "https://" {
				v0.HttpsBlock += 1
			}
			urlSet[url] = NothingV
			if len(v0.Domain) == 0 {
				DumpSnap.AddDomain(domain, v.U2Hash)
			}
		}
	}
	for _, value := range o.Url {
		url, domain := NormalizeUrl(value.Url)
		if _, ok := urlSet[url]; !ok {
			DumpSnap.DeleteUrl(url, o.U2Hash)
		}
		if len(v0.Domain) == 0 {
			if _, ok := domainSet[url]; !ok {
				DumpSnap.DeleteDomain(domain, o.U2Hash)
			}
		}
	}
}

func getContentId(_e xml.StartElement) int32 {
	var (
		id  int
		err error
	)
	for _, _a := range _e.Attr {
		if _a.Name.Local == "id" {
			id, err = strconv.Atoi(_a.Value)
			if err != nil {
				Debug.Printf("Can't fetch id: %s: %s\n", _a.Value, err.Error())
			}
		}
	}
	return int32(id)
}

func handleRegister(element xml.StartElement, r *TReg) {
	for _, attr := range element.Attr {
		switch attr.Name.Local {
		case "date":
			r.UpdateTime = parseTimeMSK(cParseResourcesDate, attr.Value)
		}
	}
}

func newMinContent(id int32, hash uint64, utime int64, pack []byte) *TMinContent {
	v := TMinContent{Id: id, U2Hash: hash, RegistryUpdateTime: utime, Pack: pack}
	return &v
}

func (v *TMinContent) newPbContent(ip4 uint32, ip6 []byte, domain, url, aggr string) *pb.Content {
	v0 := pb.Content{}
	v0.BlockType = v.BlockType
	v0.RegistryUpdateTime = v.RegistryUpdateTime
	v0.Id = v.Id
	v0.Ip4 = ip4
	v0.Domain = domain
	v0.Url = url
	v0.Pack = v.Pack
	return &v0
}

func parseInt32(to *int32, value string) error {
	i, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*to = int32(i)
	return nil
}
