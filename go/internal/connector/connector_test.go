// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package connector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

type testResolver struct {
	txt      []string
	srv      map[string][]*net.SRV
	queries  []string
	txtError error
}

func (r *testResolver) LookupTXT(context.Context, string) ([]string, error) {
	return r.txt, r.txtError
}

func (r *testResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	r.queries = append(r.queries, service+"/"+proto+"/"+name)
	return "", r.srv[proto], nil
}

func TestHTTPConnectorRedirectAndHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("X-Network-Name"), "test-network"; got != want {
			t.Errorf("X-Network-Name = %q, want %q", got, want)
		}
		w.Header().Set("Location", "/?peers=tcp%3A%2F%2Frelay.example%3A11010+udp%3A%2F%2Frelay.example%3A11010")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	connector, err := NewHTTPConnector(server.URL, "test-network")
	if err != nil {
		t.Fatal(err)
	}
	got, err := connector.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []config.Endpoint{
		{Scheme: "tcp", Protocol: config.ProtocolTCP, Host: "relay.example", Port: 11010},
		{Scheme: "udp", Protocol: config.ProtocolUDP, Host: "relay.example", Port: 11010},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Discover() = %#v, want %#v", got, want)
	}
}

func TestHTTPConnectorBodyAndResponseLimit(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []config.Endpoint
	}{
		{
			name: "whitespace separated",
			body: "invalid\ntcp://one.example:11010 udp://two.example:11010",
			want: []config.Endpoint{
				{Scheme: "tcp", Protocol: config.ProtocolTCP, Host: "one.example", Port: 11010},
				{Scheme: "udp", Protocol: config.ProtocolUDP, Host: "two.example", Port: 11010},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			connector, err := NewHTTPConnector(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := connector.Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Discover() = %#v, want %#v", got, test.want)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseSize+1)))
	}))
	defer server.Close()
	connector, err := NewHTTPConnector(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.Discover(context.Background()); err == nil {
		t.Fatal("Discover() accepted an oversized response")
	}
}

func TestTXTConnector(t *testing.T) {
	resolver := &testResolver{txt: []string{"tcp://one.example:11010 udp://two.example:11010"}}
	connector := NewTXTConnector("peers.example", resolver)
	got, err := connector.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Host != "one.example" || got[1].Protocol != config.ProtocolUDP {
		t.Fatalf("Discover() = %#v", got)
	}
}

func TestSRVConnectorPriorityAndQueries(t *testing.T) {
	resolver := &testResolver{srv: map[string][]*net.SRV{
		"tcp": {
			{Target: "low.example.", Port: 11010, Priority: 10, Weight: 1},
			{Target: "high.example.", Port: 11010, Priority: 20, Weight: 100},
		},
		"udp": {{Target: "udp.example.", Port: 11010, Priority: 10, Weight: 1}},
	}}
	connector := NewSRVConnector("example", resolver)
	got, err := connector.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || (got[0].Host != "low.example" && got[0].Host != "udp.example") {
		t.Fatalf("Discover() = %#v", got)
	}
	for _, query := range resolver.queries {
		if !strings.HasPrefix(query, "easytier/") {
			t.Errorf("unexpected SRV query %q", query)
		}
	}
	if len(resolver.queries) != len(srvSchemes) {
		t.Fatalf("got %d SRV queries, want %d", len(resolver.queries), len(srvSchemes))
	}
}

func TestConnectorsHonorContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewTXTConnector("example", &testResolver{}).Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("TXT Discover() error = %v, want context.Canceled", err)
	}
	if _, err := NewSRVConnector("example", &testResolver{}).Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("SRV Discover() error = %v, want context.Canceled", err)
	}
}
