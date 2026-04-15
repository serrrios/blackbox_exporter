package prober

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestProbeOpenSSLHTTPSuccessMetrics(t *testing.T) {
	listener := newTestTCPListener(t)
	defer listener.Close()

	restore := stubGOSTOpenSSL(
		func(_ context.Context, connectAddress, serverName string, opensslConfig config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error) {
			if connectAddress == "" || serverName == "" || opensslConfig.OpenSSLBinary != "" {
				// The probe should provide both connect address and server name.
			}
			return openSSLTLSMetadata{
				EarliestCertExpiry: time.Unix(1893456000, 0),
				LastChainExpiry:    time.Unix(1893456000, 0),
				Fingerprint:        "abc123",
				Subject:            "CN=localhost",
				Issuer:             "CN=test-ca",
				DNSNames:           "localhost",
				SerialNumber:       "01",
				Version:            "TLSv1.2",
				Cipher:             "GOST2012-GOST8912-GOST8912",
			}, nil
		},
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe, _ *http.Request) ([]byte, time.Duration, time.Duration, string, error) {
			raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: application/json\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n{\"ok\":true}")
			return raw, 5 * time.Millisecond, 8 * time.Millisecond, "", nil
		},
	)
	defer restore()

	target := "https://localhost:" + listener.Port() + "/health"
	registry := prometheus.NewPedanticRegistry()
	module := config.Module{
		Timeout: time.Second,
		OpenSSLHTTP: config.OpenSSLHTTPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			FollowRedirects:    true,
			OpenSSLBinary:      "openssl",
		},
	}

	result := ProbeOpenSSLHTTP(context.Background(), target, module, registry, promslog.NewNopLogger())
	if !result {
		t.Fatal("expected openssl_http probe to succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}

	checkRegistryResults(map[string]float64{
		"probe_http_status_code":                      200,
		"probe_http_ssl":                              1,
		"probe_http_version":                          1.1,
		"probe_http_redirects":                        0,
		"probe_ssl_earliest_cert_expiry":              1893456000,
		"probe_ssl_last_chain_expiry_timestamp_seconds": 1893456000,
		"probe_ip_protocol":                           4,
	}, mfs, t)

	checkRegistryLabels(map[string]map[string]string{
		"probe_tls_version_info": {
			"version": "TLSv1.2",
		},
		"probe_tls_cipher_info": {
			"cipher": "GOST2012-GOST8912-GOST8912",
		},
		"probe_ssl_last_chain_info": {
			"fingerprint_sha256": "abc123",
			"subject":            "CN=localhost",
			"issuer":             "CN=test-ca",
			"subjectalternative": "localhost",
			"serialnumber":       "01",
		},
	}, mfs, t)

	assertMetricPresent(t, mfs, "probe_ip_info")
}

func TestProbeOpenSSLHTTPFollowsRedirects(t *testing.T) {
	listener := newTestTCPListener(t)
	defer listener.Close()

	callCount := 0
	restore := stubGOSTOpenSSL(
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error) {
			return openSSLTLSMetadata{
				EarliestCertExpiry: time.Unix(1893456000, 0),
				LastChainExpiry:    time.Unix(1893456000, 0),
			}, nil
		},
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe, _ *http.Request) ([]byte, time.Duration, time.Duration, string, error) {
			callCount++
			if callCount == 1 {
				raw := []byte("HTTP/1.1 302 Found\r\nLocation: /ready\r\nContent-Length: 0\r\n\r\n")
				return raw, 2 * time.Millisecond, 4 * time.Millisecond, "", nil
			}
			raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			return raw, 2 * time.Millisecond, 4 * time.Millisecond, "", nil
		},
	)
	defer restore()

	target := "https://localhost:" + listener.Port() + "/redirect"
	registry := prometheus.NewPedanticRegistry()
	module := config.Module{
		Timeout: time.Second,
		OpenSSLHTTP: config.OpenSSLHTTPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			FollowRedirects:    true,
			OpenSSLBinary:      "openssl",
		},
	}

	result := ProbeOpenSSLHTTP(context.Background(), target, module, registry, promslog.NewNopLogger())
	if !result {
		t.Fatal("expected openssl_http redirect probe to succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}

	checkRegistryResults(map[string]float64{
		"probe_http_status_code": 200,
		"probe_http_redirects":   1,
	}, mfs, t)
}

func TestProbeOpenSSLHTTPStatusMismatchStillExposesMetrics(t *testing.T) {
	listener := newTestTCPListener(t)
	defer listener.Close()

	restore := stubGOSTOpenSSL(
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error) {
			return openSSLTLSMetadata{
				EarliestCertExpiry: time.Unix(1893456000, 0),
				LastChainExpiry:    time.Unix(1893456000, 0),
				Fingerprint:        "abc123",
				Subject:            "CN=localhost",
				Issuer:             "CN=test-ca",
				DNSNames:           "localhost",
				SerialNumber:       "01",
				Version:            "TLSv1.2",
				Cipher:             "AES128-SHA",
			}, nil
		},
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe, _ *http.Request) ([]byte, time.Duration, time.Duration, string, error) {
			raw := []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\n\r\nno")
			return raw, 1, 2, "", nil
		},
	)
	defer restore()

	target := "https://localhost:" + listener.Port() + "/"
	registry := prometheus.NewPedanticRegistry()
	module := config.Module{
		Timeout: time.Second,
		OpenSSLHTTP: config.OpenSSLHTTPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			FollowRedirects:    false,
			OpenSSLBinary:      "openssl",
			ValidStatusCodes:   []int{200},
		},
	}

	if ProbeOpenSSLHTTP(context.Background(), target, module, registry, promslog.NewNopLogger()) {
		t.Fatal("expected probe to fail on HTTP 400 vs valid_status_codes")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	checkRegistryResults(map[string]float64{
		"probe_http_status_code":         400,
		"probe_http_ssl":                 1,
		"probe_ssl_earliest_cert_expiry": 1893456000,
	}, mfs, t)
	assertMetricPresent(t, mfs, "probe_ssl_last_chain_info")
}

func stubGOSTOpenSSL(
	meta func(context.Context, string, string, config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error),
	request func(context.Context, string, string, config.OpenSSLHTTPProbe, *http.Request) ([]byte, time.Duration, time.Duration, string, error),
) func() {
	origMeta := openSSLHTTPMetadataFetcher
	origRequest := openSSLHTTPRequestRunner
	openSSLHTTPMetadataFetcher = meta
	openSSLHTTPRequestRunner = request
	return func() {
		openSSLHTTPMetadataFetcher = origMeta
		openSSLHTTPRequestRunner = origRequest
	}
}

func newTestTCPListener(t *testing.T) testTCPListener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
				default:
				}
				return
			}
			_ = conn.Close()
		}
	}()

	return testTCPListener{Listener: ln, done: done}
}

type testTCPListener struct {
	net.Listener
	done chan struct{}
}

func (l testTCPListener) Port() string {
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

func (l testTCPListener) Close() error {
	close(l.done)
	return l.Listener.Close()
}

func assertMetricPresent(t *testing.T, mfs []*dto.MetricFamily, metric string) {
	t.Helper()
	for _, mf := range mfs {
		if mf.GetName() == metric {
			return
		}
	}
	t.Fatalf("expected metric %s to be present", metric)
}

func TestSanitizeProbeSSLChainLabel(t *testing.T) {
	const cyr = "ПАО \"МОСКОВСКИЙ КРЕДИТНЫЙ БАНК\""
	if got := sanitizeProbeSSLChainLabel(cyr, 256); got != cyr {
		t.Fatalf("short string changed: %q", got)
	}
	long := strings.Repeat("а", 500) // 2 bytes per rune in UTF-8
	got := sanitizeProbeSSLChainLabel(long, 400)
	if len(got) > 400 {
		t.Fatalf("expected len <= 400, got %d", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8 after truncate: %q", got)
	}
}

func TestParseOpenSSLHTTPResponseTrimsOpenSSLNoise(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("request creation failed: %v", err)
	}

	raw := []byte("CONNECTED(00000003)\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	resp, err := parseOpenSSLHTTPResponse(raw, req)
	if err != nil {
		t.Fatalf("parse response failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestNormalizeOpenSSLHTTPTarget(t *testing.T) {
	tests := map[string]string{
		"localhost:9443":             "https://localhost:9443",
		"http://localhost:9443":      "https://localhost:9443",
		"https://localhost:9443/foo": "https://localhost:9443/foo",
	}
	for input, expected := range tests {
		if actual := normalizeOpenSSLHTTPTarget(input); actual != expected {
			t.Fatalf("normalizeOpenSSLHTTPTarget(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestOpenSSLHTTPServerNameUsesHostHeader(t *testing.T) {
	serverName := getOpenSSLHTTPServerName("127.0.0.1", config.OpenSSLHTTPProbe{
		Headers: map[string]string{"Host": "tls.example.internal"},
	})
	if serverName != "tls.example.internal" {
		t.Fatalf("expected host header to drive server name, got %q", serverName)
	}
}

func TestProbeOpenSSLHTTPConnectsToRequestedPort(t *testing.T) {
	listener := newTestTCPListener(t)
	defer listener.Close()

	var capturedAddress string
	restore := stubGOSTOpenSSL(
		func(_ context.Context, connectAddress, _ string, _ config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error) {
			capturedAddress = connectAddress
			return openSSLTLSMetadata{}, nil
		},
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe, _ *http.Request) ([]byte, time.Duration, time.Duration, string, error) {
			raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			return raw, time.Millisecond, 2 * time.Millisecond, "", nil
		},
	)
	defer restore()

	registry := prometheus.NewPedanticRegistry()
	module := config.Module{
		OpenSSLHTTP: config.OpenSSLHTTPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			FollowRedirects:    true,
			OpenSSLBinary:      "openssl",
		},
	}
	target := "https://localhost:" + listener.Port()
	if !ProbeOpenSSLHTTP(context.Background(), target, module, registry, promslog.NewNopLogger()) {
		t.Fatal("expected probe to succeed")
	}

	if _, port, _ := net.SplitHostPort(capturedAddress); port != listener.Port() {
		t.Fatalf("expected captured port %s, got %s", listener.Port(), port)
	}
}

func TestProbeOpenSSLHTTPExposesHTTPVersionMetric(t *testing.T) {
	listener := newTestTCPListener(t)
	defer listener.Close()

	restore := stubGOSTOpenSSL(
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error) {
			return openSSLTLSMetadata{}, nil
		},
		func(_ context.Context, _, _ string, _ config.OpenSSLHTTPProbe, _ *http.Request) ([]byte, time.Duration, time.Duration, string, error) {
			raw := []byte("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
			return raw, time.Millisecond, 2 * time.Millisecond, "", nil
		},
	)
	defer restore()

	registry := prometheus.NewPedanticRegistry()
	module := config.Module{
		OpenSSLHTTP: config.OpenSSLHTTPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			FollowRedirects:    true,
			OpenSSLBinary:      "openssl",
		},
	}
	target := "https://localhost:" + listener.Port()
	if !ProbeOpenSSLHTTP(context.Background(), target, module, registry, promslog.NewNopLogger()) {
		t.Fatal("expected probe to succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	checkRegistryResults(map[string]float64{"probe_http_version": 1}, mfs, t)
}

func TestTestTCPListenerPortHelper(t *testing.T) {
	listener := newTestTCPListener(t)
	defer listener.Close()
	if _, err := strconv.Atoi(listener.Port()); err != nil {
		t.Fatalf("expected numeric port, got %q", listener.Port())
	}
}
