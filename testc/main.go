//go:generate protoc -I ../msg --go_out=plugins=grpc:../msg ../msg/msg.proto

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	pb "github.com/usher2/u2byckdump/msg"
	"golang.org/x/net/idna"
	"google.golang.org/grpc"
)

const (
	TBLOCK_UNKNOWN = iota
	TBLOCK_URL
	TBLOCK_HTTPS
	TBLOCK_DOMAIN
	TBLOCK_IP
)

type TContent struct {
	Id          int32     `json:"id"`
	Description string    `json:"d"` // info
	IncludeTime int64     `json:"it"`
	Url         []TUrl    `json:"url,omitempty"`
	Ip4         []TIp4    `json:"ip4,omitempty"`
	Domain      []TDomain `json:"dm,omitempty"`
	HttpsBlock  int       `json:"hb"`
	U2Hash      uint64    `json:"u2h"`
}

type TDomain struct {
	Domain string `json:"dm"`
}

type TUrl struct {
	Url string `json:"u"`
}

type TIp4 struct {
	Ip4 uint32 `json:"ip4"`
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func NormalizeDomain(domain string) string {
	domain = strings.Replace(domain, ",", ".", -1)
	domain = strings.Replace(domain, " ", "", -1)
	if _c := strings.IndexByte(domain, '/'); _c >= 0 {
		domain = domain[:_c]
	}
	if _c := strings.IndexByte(domain, '\\'); _c >= 0 {
		domain = domain[:_c]
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain, _ = idna.ToASCII(domain)
	domain = strings.ToLower(domain)
	return domain
}

func NormalizeUrl(u string) string {
	u = strings.Replace(u, "\\", "/", -1)
	_url, err := url.Parse(u)
	if err != nil {
		fmt.Printf("URL parse error: %s\n", err.Error())
		// add as is
		return u
	} else {
		port := ""
		domain := _url.Hostname()
		colon := strings.LastIndexByte(domain, ':')
		if colon != -1 && validOptionalPort(domain[colon:]) {
			domain, port = domain[:colon], domain[colon+1:]
		}
		domain = NormalizeDomain(domain)
		_url.Host = domain
		if port != "" {
			_url.Host = _url.Host + ":" + port
		}
		_url.Fragment = ""
		return _url.String()
	}
}

func parseIp4(s string) uint32 {
	var ip, n uint32 = 0, 0
	var r uint = 24
	for i := 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			n = n*10 + uint32(s[i]-'0')
			if n > 0xFF {
				//Debug.Printf("Bad IP (1) n=%d: %s\n", n, s)
				return 0xFFFFFFFF
			}
		} else if s[i] == '.' {
			if r != 0 {
				ip = ip + (n << r)
			} else {
				//Debug.Printf("Bad IP (2): %s\n", s)
				return 0xFFFFFFFF
			}
			r = r - 8
			n = 0
		} else {
			//Debug.Printf("Bad IP (3): %s\n", s)
			return 0xFFFFFFFF
		}
	}
	if r != 0 {
		//Debug.Printf("Bad IP (4): %s\n", s)
		return 0xFFFFFFFF
	}
	ip = ip + n
	return ip
}

func printContent(packet *pb.Content) {
	content := TContent{}
	err := json.Unmarshal(packet.Pack, &content)
	if err != nil {
		fmt.Printf("Oooops!!! %s\n", err)

		return
	}
	switch packet.BlockType {
	case TBLOCK_IP:
		fmt.Print("IP block. ")
	case TBLOCK_URL:
		fmt.Print("URL block. ")
	case TBLOCK_HTTPS:
		fmt.Print("HTTPS URL block. ")
	case TBLOCK_DOMAIN:
		fmt.Print("Domain block. ")
	default:
		fmt.Print("UNKNOWN block. ")
	}

	fmt.Printf("#%d %s \nAdded: %s\n", content.Id, content.Description, time.Unix(content.IncludeTime, 0).Format("2006-01-02"))
	fmt.Printf("    \\_IPv4: %d, URL: %d, Domains: %d\n",
		len(content.Ip4), len(content.Url), len(content.Domain))
}

func searchID(c pb.CheckClient) {
	ids := []int32{33, 100, 79682}
	for _, id := range ids {
		fmt.Printf("Looking for content: %d\n", id)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchID(ctx, &pb.IDRequest{Query: uint64(id)})
		if err != nil {
			fmt.Printf("%v.SearchID(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchIP(c pb.CheckClient) {
	ips := []string{"1.1.1.1", "8.8.8.8", "82.209.241.131"}
	for _, ip := range ips {
		fmt.Printf("Looking for %s\n", ip)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchIP4(ctx, &pb.IP4Request{Query: parseIp4(ip)})
		if err != nil {
			fmt.Printf("%v.SearchIP4(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchURL(c pb.CheckClient) {
	urls := []string{"https://kupi-klad.cc", "http://legalparty.org", "https://usher2.club/articles"}
	for _, u := range urls {
		_url := NormalizeUrl(u)
		if _url != u {
			fmt.Printf("Input was %s\n", u)
		}
		fmt.Printf("Looking for %s\n", _url)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchURL(ctx, &pb.URLRequest{Query: _url})
		if err != nil {
			fmt.Printf("%v.SearchURL(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchDomain(c pb.CheckClient) {
	domains := []string{"www.toprc.biz ", "stulchik.net", "usher2.club", "by.legalizer.info"}
	for _, domain := range domains {
		_domain := NormalizeDomain(domain)
		if _domain != domain {
			fmt.Printf("Input was %s\n", domain)
		}
		fmt.Printf("Looking for %s\n", _domain)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchDomain(ctx, &pb.DomainRequest{Query: NormalizeDomain(domain)})
		if err != nil {
			fmt.Printf("%v.SearchURL(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func makePing(c pb.CheckClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.Ping(ctx, &pb.PingRequest{Ping: "How are you?"})
	if err != nil {
		fmt.Printf("%v.Ping(_) = _, %v\n", c, err)
	}
	fmt.Printf("Pong: %s\n", r.Pong)
}

func main() {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.Dial("localhost:50002", opts...)
	if err != nil {
		fmt.Printf("fail to dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("Connect...\n")
	c := pb.NewCheckClient(conn)
	makePing(c)
	searchID(c)
	searchIP(c)
	searchURL(c)
	searchDomain(c)
	makePing(c)
}
