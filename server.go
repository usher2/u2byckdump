package main

//go:generate protoc -I msg --go-grpc_out=msg --go_out=msg --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative msg/msg.proto

import (
	"context"

	pb "github.com/usher2/u2byckdump/msg"
)

type server struct {
	pb.UnimplementedCheckServer
}

func (s *server) SearchID(ctx context.Context, in *pb.IDRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received content ID: %d\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		Debug.Printf("ut: %d", DumpSnap.utime)
		if v, ok := DumpSnap.Content[query]; ok {
			Debug.Printf("SearchID JSON: %s\n", v.Pack)
			r.Results = make([]*pb.Content, 1)
			r.Results[0] = v.newPbContent(0, nil, "", "", "")
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Данные не готовы"}, nil
	}
}

func (s *server) SearchIP4(c context.Context, in *pb.IP4Request) (*pb.SearchResponse, error) {
	var v1 ArrayIntSet
	query := in.GetQuery()
	ipb := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, byte((query & 0xFF000000) >> 24), byte((query & 0x00FF0000) >> 16), byte((query & 0x0000FF00) >> 8), byte(query & 0x000000FF)}
	Debug.Printf("Received IPv4: %d.%d.%d.%d\n", ipb[12], ipb[13], ipb[14], ipb[15])
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		Debug.Printf("ut: %d", DumpSnap.utime)
		if a, ok := DumpSnap.ip[query]; ok {
			for _, id := range a {
				v1 = append(v1, id)
			}
		}
		r.Results = make([]*pb.Content, len(v1))
		j := 0
		for _, id := range v1 {
			if v, ok := DumpSnap.Content[id]; ok {
				Debug.Printf("SearchIP4 JSON: %s\n", v.Pack)
				r.Results[j] = v.newPbContent(query, nil, "", "", "")
				j++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Данные не готовы"}, nil
	}
}

func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received URL: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		Debug.Printf("ut: %d", DumpSnap.utime)
		a := DumpSnap.url[query]
		r.Results = make([]*pb.Content, len(a))
		i := 0
		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				Debug.Printf("SearchURL JSON: %s\n", v.Pack)
				r.Results[i] = v.newPbContent(0, nil, "", query, "")
				i++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Данные не готовы"}, nil
	}
}

func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received Domain: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		Debug.Printf("ut: %d", DumpSnap.utime)
		a := DumpSnap.domain[query]
		Debug.Printf("SearchDomain (%d) %v\n", len(a), a)
		r.Results = make([]*pb.Content, len(a))
		i := 0
		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				Debug.Printf("SearchDomain JSON: %s\n", v.Pack)
				r.Results[i] = v.newPbContent(0, nil, query, "", "")
				i++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Данные не готовы"}, nil
	}
}
func (s *server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PongResponse, error) {
	ping := in.GetPing()
	Debug.Printf("Received Ping: %v\n", ping)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.PongResponse{Pong: "Я внимаю, мой повелитель\n", RegistryUpdateTime: DumpSnap.utime}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.PongResponse{Error: "Данные не готовы"}, nil
	}
}
