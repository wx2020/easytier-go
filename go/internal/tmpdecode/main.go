package main

import (
	"fmt"
	"os"

	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	msg := &managepb.CollectNetworkInfoResponse{}
	if err := proto.Unmarshal(raw, msg); err != nil {
		panic(err)
	}
	m := protojson.MarshalOptions{UseProtoNames: true, Multiline: true}
	out, err := m.Marshal(msg)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
