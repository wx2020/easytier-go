// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package connector discovers EasyTier tunnel endpoints from HTTP and DNS.
package connector

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

// MaxResponseSize is the maximum HTTP discovery response body accepted.
const MaxResponseSize = 1 << 20

// DiscoveryConnector resolves one discovery source into tunnel endpoints.
type DiscoveryConnector interface {
	Discover(context.Context) ([]config.Endpoint, error)
}

// Resolver is the DNS subset used by the DNS discovery connectors.
// net.Resolver implements Resolver and tests can provide a local implementation.
type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
}

// HTTPConnector discovers tunnel endpoints from an HTTP or HTTPS URL.
type HTTPConnector struct {
	URL         string
	NetworkName string
	Client      *http.Client
}

// NewHTTPConnector validates rawURL and creates an HTTP discovery connector.
func NewHTTPConnector(rawURL, networkName string) (*HTTPConnector, error) {
	if err := validateDiscoveryURL(rawURL); err != nil {
		return nil, err
	}
	return &HTTPConnector{URL: rawURL, NetworkName: networkName}, nil
}

// Discover performs one GET without following redirects.
func (c *HTTPConnector) Discover(ctx context.Context) ([]config.Endpoint, error) {
	if c == nil {
		return nil, fmt.Errorf("HTTP connector is nil")
	}
	if err := validateDiscoveryURL(c.URL); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create HTTP discovery request: %w", err)
	}
	request.Header.Set("X-Network-Name", c.NetworkName)

	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := clientCopy.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTP discovery request: %w", err)
	}
	defer response.Body.Close()

	body, err := readBounded(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read HTTP discovery response: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	switch {
	case response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest:
		location := response.Header.Get("Location")
		if location == "" {
			return nil, fmt.Errorf("HTTP discovery redirect has no Location header")
		}
		return parseRedirect(location, c.URL)
	case response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices:
		return parseEndpointFields(string(body), "HTTP discovery response")
	default:
		return nil, fmt.Errorf("HTTP discovery returned status %s", response.Status)
	}
}

// TXTConnector discovers tunnel endpoints from a DNS TXT record.
type TXTConnector struct {
	Domain   string
	Resolver Resolver
}

// NewTXTConnector creates a TXT discovery connector. An omitted resolver uses
// net.DefaultResolver.
func NewTXTConnector(domain string, resolvers ...Resolver) *TXTConnector {
	return &TXTConnector{Domain: domain, Resolver: chooseResolver(resolvers)}
}

// Discover looks up TXT data and parses its space-separated tunnel URLs.
func (c *TXTConnector) Discover(ctx context.Context) ([]config.Endpoint, error) {
	if c == nil {
		return nil, fmt.Errorf("TXT connector is nil")
	}
	domain, err := validateDomain(c.Domain)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("lookup TXT record %q: %w", domain, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return parseEndpointFields(strings.Join(records, " "), "DNS TXT record")
}

// SRVConnector discovers one tunnel endpoint using EasyTier SRV records.
type SRVConnector struct {
	Domain   string
	Resolver Resolver
}

// NewSRVConnector creates an SRV discovery connector. An omitted resolver uses
// net.DefaultResolver.
func NewSRVConnector(domain string, resolvers ...Resolver) *SRVConnector {
	return &SRVConnector{Domain: domain, Resolver: chooseResolver(resolvers)}
}

// Discover queries _easytier._<scheme>.<domain> for every tunnel scheme and
// selects a record according to the DNS SRV priority and weight rules.
func (c *SRVConnector) Discover(ctx context.Context) ([]config.Endpoint, error) {
	if c == nil {
		return nil, fmt.Errorf("SRV connector is nil")
	}
	domain, err := validateDomain(c.Domain)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	var candidates []srvCandidate
	var lastErr error
	for _, scheme := range srvSchemes {
		_, records, lookupErr := resolver.LookupSRV(ctx, "easytier", scheme, domain)
		if lookupErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = lookupErr
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, record := range records {
			candidate, parseErr := parseSRVCandidate(scheme, record)
			if parseErr != nil {
				lastErr = parseErr
				continue
			}
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no valid EasyTier SRV record for %q: %w", domain, lastErr)
		}
		return nil, fmt.Errorf("no valid EasyTier SRV record for %q", domain)
	}

	selected := selectSRV(candidates)
	return []config.Endpoint{selected.endpoint}, nil
}

var srvSchemes = []string{
	string(config.ProtocolTCP),
	string(config.ProtocolUDP),
	string(config.ProtocolWG),
	string(config.ProtocolQUIC),
	string(config.ProtocolWS),
	string(config.ProtocolWSS),
	string(config.ProtocolFakeTCP),
}

type srvCandidate struct {
	endpoint config.Endpoint
	priority uint16
	weight   uint16
}

func chooseResolver(resolvers []Resolver) Resolver {
	if len(resolvers) != 0 {
		return resolvers[0]
	}
	return net.DefaultResolver
}

func validateDiscoveryURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse discovery URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("discovery URL %q must use http or https", raw)
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid HTTP discovery URL %q", raw)
	}
	return nil
}

func validateDomain(raw string) (string, error) {
	domain := strings.TrimSpace(raw)
	if domain == "" || strings.ContainsAny(domain, " \t\r\n") {
		return "", fmt.Errorf("DNS discovery domain %q is invalid", raw)
	}
	return domain, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, MaxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxResponseSize {
		return nil, fmt.Errorf("response exceeds %d bytes", MaxResponseSize)
	}
	return body, nil
}

func parseRedirect(location, base string) ([]config.Endpoint, error) {
	redirect, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URL %q: %w", location, err)
	}
	if redirect.IsAbs() && redirect.Scheme != "http" && redirect.Scheme != "https" {
		endpoint, parseErr := config.ParseEndpoint(location)
		if parseErr != nil {
			return nil, fmt.Errorf("parse redirect endpoint %q: %w", location, parseErr)
		}
		return []config.Endpoint{endpoint}, nil
	}
	if !redirect.IsAbs() {
		baseURL, baseErr := url.Parse(base)
		if baseErr != nil {
			return nil, fmt.Errorf("parse discovery URL %q: %w", base, baseErr)
		}
		redirect = baseURL.ResolveReference(redirect)
	}
	values := redirect.Query()["peers"]
	if len(values) == 0 {
		return nil, fmt.Errorf("redirect URL %q has no peers query parameter", location)
	}
	return parseEndpointFields(strings.Join(values, " "), "HTTP redirect peers")
}

func parseEndpointFields(value, source string) ([]config.Endpoint, error) {
	fields := strings.Fields(value)
	endpoints := make([]config.Endpoint, 0, len(fields))
	for _, field := range fields {
		endpoint, err := config.ParseEndpoint(field)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("%s contains no valid tunnel URLs", source)
	}
	return endpoints, nil
}

func parseSRVCandidate(scheme string, record *net.SRV) (srvCandidate, error) {
	if record == nil || record.Port == 0 || record.Target == "" || record.Target == "." {
		return srvCandidate{}, fmt.Errorf("invalid SRV record for %s", scheme)
	}
	host := strings.TrimSuffix(record.Target, ".")
	if host == "" || strings.ContainsAny(host, "/?#") {
		return srvCandidate{}, fmt.Errorf("invalid SRV target %q", record.Target)
	}
	raw := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(int(record.Port)))
	endpoint, err := config.ParseEndpoint(raw)
	if err != nil {
		return srvCandidate{}, err
	}
	return srvCandidate{endpoint: endpoint, priority: record.Priority, weight: record.Weight}, nil
}

func selectSRV(candidates []srvCandidate) srvCandidate {
	priority := candidates[0].priority
	for _, candidate := range candidates[1:] {
		if candidate.priority < priority {
			priority = candidate.priority
		}
	}

	eligible := candidates[:0]
	var total uint64
	for _, candidate := range candidates {
		if candidate.priority == priority {
			eligible = append(eligible, candidate)
			total += uint64(candidate.weight)
		}
	}
	if total == 0 {
		return eligible[rand.Intn(len(eligible))]
	}
	pick := uint64(rand.Int63n(int64(total)))
	for _, candidate := range eligible {
		if pick < uint64(candidate.weight) {
			return candidate
		}
		pick -= uint64(candidate.weight)
	}
	return eligible[len(eligible)-1]
}
