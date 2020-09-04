package main

type TXMLDomain struct {
	Domain string `xml:",chardata"`
}

type TXMLUrl struct {
	Url string `xml:",chardata"`
}

type TXMLIp struct {
	Ip string `xml:",chardata"`
}
