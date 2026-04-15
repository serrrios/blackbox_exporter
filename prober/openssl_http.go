// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/blackbox_exporter/config"
)

// opensslInterleavedCapture merges s_client stdout and stderr in arrival order (like a TTY).
// openssl prints the TLS session to stderr and decrypted HTTP to stdout; buffering them
// separately then concatenating breaks interleaved output and can hide the HTTP response.
type opensslInterleavedCapture struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	start     time.Time
	firstSeen bool
	firstDur  time.Duration
}

func newOpenSSLInterleavedCapture(start time.Time) *opensslInterleavedCapture {
	return &opensslInterleavedCapture{start: start}
}

func (c *opensslInterleavedCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	if len(p) > 0 && !c.firstSeen {
		c.firstSeen = true
		c.firstDur = time.Since(c.start)
	}
	n, err := c.buf.Write(p)
	c.mu.Unlock()
	return n, err
}

func (c *opensslInterleavedCapture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Bytes()
}

func (c *opensslInterleavedCapture) firstByteElapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.firstSeen {
		return 0
	}
	return c.firstDur
}

type openSSLTLSMetadata struct {
	EarliestCertExpiry time.Time
	LastChainExpiry    time.Time
	Fingerprint        string
	Subject            string
	Issuer             string
	DNSNames           string
	SerialNumber       string
	Version            string
	Cipher             string
}

var (
	openSSLHTTPMetadataFetcher = fetchOpenSSLHTTPMetadata
	openSSLHTTPRequestRunner   = executeOpenSSLHTTPRequest
)

// emitOpenSSLHTTPResponseMetrics publishes HTTP response and TLS metadata metrics for the final
// round trip, matching ProbeHTTP: status, body sizes and cert info are exposed even when the
// probe will fail (e.g. non-matching status code).
func emitOpenSSLHTTPResponseMetrics(
	registry *prometheus.Registry,
	finalResp *http.Response,
	finalMetadata openSSLTLSMetadata,
	finalBodyBytes int64,
	redirects int,
	redirectsGauge prometheus.Gauge,
	statusCodeGauge prometheus.Gauge,
	contentLengthGauge prometheus.Gauge,
	bodyUncompressedLengthGauge prometheus.Gauge,
	isSSLGauge prometheus.Gauge,
	probeHTTPLastModified prometheus.Gauge,
	probeSSLEarliestCertExpiryGauge prometheus.Gauge,
	probeSSLLastChainExpiryGauge prometheus.Gauge,
	probeTLSVersion *prometheus.GaugeVec,
	probeTLSCipher *prometheus.GaugeVec,
	probeSSLLastInformation *prometheus.GaugeVec,
) {
	if finalResp == nil {
		return
	}
	redirectsGauge.Set(float64(redirects))
	statusCodeGauge.Set(float64(finalResp.StatusCode))
	contentLengthGauge.Set(float64(finalResp.ContentLength))
	bodyUncompressedLengthGauge.Set(float64(finalBodyBytes))
	isSSLGauge.Set(1)
	if t, err := http.ParseTime(finalResp.Header.Get("Last-Modified")); err == nil {
		registry.MustRegister(probeHTTPLastModified)
		probeHTTPLastModified.Set(float64(t.Unix()))
	}
	if finalMetadata.EarliestCertExpiry.Unix() > 0 {
		registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeTLSVersion, probeTLSCipher, probeSSLLastChainExpiryGauge, probeSSLLastInformation)
		probeSSLEarliestCertExpiryGauge.Set(float64(finalMetadata.EarliestCertExpiry.Unix()))
		if finalMetadata.LastChainExpiry.IsZero() {
			probeSSLLastChainExpiryGauge.Set(float64(finalMetadata.EarliestCertExpiry.Unix()))
		} else {
			probeSSLLastChainExpiryGauge.Set(float64(finalMetadata.LastChainExpiry.Unix()))
		}
		if finalMetadata.Version != "" {
			probeTLSVersion.WithLabelValues(finalMetadata.Version).Set(1)
		}
		if finalMetadata.Cipher != "" {
			probeTLSCipher.WithLabelValues(finalMetadata.Cipher).Set(1)
		}
		probeSSLLastInformation.WithLabelValues(
			sanitizeProbeSSLChainLabel(finalMetadata.Fingerprint, 128),
			sanitizeProbeSSLChainLabel(finalMetadata.Subject, 4096),
			sanitizeProbeSSLChainLabel(finalMetadata.Issuer, 4096),
			sanitizeProbeSSLChainLabel(finalMetadata.DNSNames, 8192),
			sanitizeProbeSSLChainLabel(finalMetadata.SerialNumber, 256),
		).Set(1)
	}
}

func ProbeOpenSSLHTTP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (success bool) {
	var redirects int
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_http_duration_seconds",
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase"})
		contentLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_content_length",
			Help: "Length of http content response",
		})
		bodyUncompressedLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_uncompressed_body_length",
			Help: "Length of uncompressed response body",
		})
		redirectsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_redirects",
			Help: "The number of redirects",
		})
		isSSLGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_ssl",
			Help: "Indicates if SSL was used for the final redirect",
		})
		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_status_code",
			Help: "Response HTTP status code",
		})
		probeSSLEarliestCertExpiryGauge = prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)
		probeSSLLastChainExpiryGauge    = prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)
		probeSSLLastInformation         = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_ssl_last_chain_info",
				Help: "Contains SSL leaf certificate information",
			},
			[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
		)
		probeTLSVersion = prometheus.NewGaugeVec(
			probeTLSInfoGaugeOpts,
			[]string{"version"},
		)
		probeTLSCipher = prometheus.NewGaugeVec(
			probeTLSCipherGaugeOpts,
			[]string{"cipher"},
		)
		probeHTTPVersionGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_version",
			Help: "Returns the version of HTTP of the probe response",
		})
		probeFailedDueToRegex = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		})
		probeFailedDueToCEL = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_cel",
			Help: "Indicates if probe failed due to CEL expression not matching",
		})
		probeHTTPLastModified = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_last_modified_timestamp_seconds",
			Help: "Returns the Last-Modified HTTP response header in unixtime",
		})
	)

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(contentLengthGauge)
	registry.MustRegister(bodyUncompressedLengthGauge)
	registry.MustRegister(redirectsGauge)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(probeHTTPVersionGauge)
	registry.MustRegister(probeFailedDueToRegex)

	opensslConfig := module.OpenSSLHTTP
	if opensslConfig.FailIfBodyJsonMatchesCEL != nil || opensslConfig.FailIfBodyJsonNotMatchesCEL != nil {
		registry.MustRegister(probeFailedDueToCEL)
	}

	for _, lv := range []string{"resolve", "connect", "tls", "processing", "transfer"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	requestBody, err := loadOpenSSLHTTPRequestBody(opensslConfig)
	if err != nil {
		logger.Error("Error loading request body", "err", err)
		return false
	}

	currentTarget := normalizeOpenSSLHTTPTarget(target)
	var finalResp *http.Response
	var finalMetadata openSSLTLSMetadata
	var finalBodyBytes int64

	for {
		roundTripStart := time.Now()
		recordIPMetrics := redirects == 0
		resp, metadata, bodyBytes, err := doOpenSSLHTTPRoundTrip(ctx, currentTarget, requestBody, module, registry, durationGaugeVec, logger, recordIPMetrics)
		if err != nil {
			logger.Error("Error for OpenSSL HTTP request", "err", err)
			return false
		}

		finalResp = resp
		finalMetadata = metadata
		finalBodyBytes = bodyBytes

		if shouldFollowOpenSSLHTTPRedirect(opensslConfig, resp, redirects) {
			location := resp.Header.Get("Location")
			logger.Info("Received redirect", "location", location)
			nextTarget, err := resolveOpenSSLHTTPRedirectTarget(currentTarget, location)
			if err != nil {
				logger.Error("Failed to resolve redirect target", "err", err)
				return false
			}
			currentTarget = nextTarget
			redirects++
			redirectsGauge.Set(float64(redirects))
			logger.Info("Continuing OpenSSL HTTP probe after redirect", "redirect_target", currentTarget, "elapsed_seconds", time.Since(roundTripStart).Seconds())
			continue
		}

		httpVersionNumber, err := strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			logger.Error("Error parsing version number from HTTP version", "err", err)
		}
		probeHTTPVersionGauge.Set(httpVersionNumber)

		success = evaluateOpenSSLHTTPResponse(ctx, resp, opensslConfig, logger, probeFailedDueToRegex, probeFailedDueToCEL)
		if !success {
			emitOpenSSLHTTPResponseMetrics(registry, resp, metadata, bodyBytes, redirects,
				redirectsGauge, statusCodeGauge, contentLengthGauge, bodyUncompressedLengthGauge, isSSLGauge,
				probeHTTPLastModified, probeSSLEarliestCertExpiryGauge, probeSSLLastChainExpiryGauge,
				probeTLSVersion, probeTLSCipher, probeSSLLastInformation)
			return false
		}

		if len(opensslConfig.ValidHTTPVersions) != 0 {
			found := false
			for _, version := range opensslConfig.ValidHTTPVersions {
				if version == resp.Proto {
					found = true
					break
				}
			}
			if !found {
				logger.Error("Invalid HTTP version number", "version", resp.Proto)
				emitOpenSSLHTTPResponseMetrics(registry, resp, metadata, bodyBytes, redirects,
					redirectsGauge, statusCodeGauge, contentLengthGauge, bodyUncompressedLengthGauge, isSSLGauge,
					probeHTTPLastModified, probeSSLEarliestCertExpiryGauge, probeSSLLastChainExpiryGauge,
					probeTLSVersion, probeTLSCipher, probeSSLLastInformation)
				return false
			}
		}
		break
	}

	emitOpenSSLHTTPResponseMetrics(registry, finalResp, finalMetadata, finalBodyBytes, redirects,
		redirectsGauge, statusCodeGauge, contentLengthGauge, bodyUncompressedLengthGauge, isSSLGauge,
		probeHTTPLastModified, probeSSLEarliestCertExpiryGauge, probeSSLLastChainExpiryGauge,
		probeTLSVersion, probeTLSCipher, probeSSLLastInformation)

	if opensslConfig.FailIfSSL {
		logger.Error("Final request was over SSL")
		return false
	}
	if opensslConfig.FailIfNotSSL {
		logger.Error("Final request was not over SSL")
		return false
	}
	return success
}

func doOpenSSLHTTPRoundTrip(ctx context.Context, target string, requestBody []byte, module config.Module, registry *prometheus.Registry, durationGaugeVec *prometheus.GaugeVec, logger *slog.Logger, recordIPMetrics bool) (*http.Response, openSSLTLSMetadata, int64, error) {
	opensslConfig := module.OpenSSLHTTP
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, openSSLTLSMetadata{}, 0, err
	}
	if targetURL.Scheme == "" {
		targetURL.Scheme = "https"
	}
	if !strings.EqualFold(targetURL.Scheme, "https") {
		return nil, openSSLTLSMetadata{}, 0, fmt.Errorf("openssl_http only supports https targets")
	}

	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()
	if targetPort == "" {
		targetPort = "443"
	}

	var ip *net.IPAddr
	var lookupTime float64
	if recordIPMetrics {
		ip, lookupTime, err = chooseProtocol(ctx, opensslConfig.IPProtocol, opensslConfig.IPProtocolFallback, targetHost, registry, logger)
		if err != nil {
			return nil, openSSLTLSMetadata{}, 0, err
		}
	} else {
		ip, lookupTime, err = resolveOpenSSLHTTPProtocol(ctx, opensslConfig.IPProtocol, opensslConfig.IPProtocolFallback, targetHost)
		if err != nil {
			return nil, openSSLTLSMetadata{}, 0, err
		}
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	connectAddress := net.JoinHostPort(ip.String(), targetPort)
	serverName := getOpenSSLHTTPServerName(targetHost, opensslConfig)

	connectStart := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", connectAddress)
	if err != nil {
		return nil, openSSLTLSMetadata{}, 0, err
	}
	durationGaugeVec.WithLabelValues("connect").Add(time.Since(connectStart).Seconds())
	_ = conn.Close()

	tlsStart := time.Now()
	metadata, err := openSSLHTTPMetadataFetcher(ctx, connectAddress, serverName, opensslConfig)
	durationGaugeVec.WithLabelValues("tls").Add(time.Since(tlsStart).Seconds())
	if err != nil {
		return nil, openSSLTLSMetadata{}, 0, err
	}

	request, err := buildOpenSSLHTTPRequest(ctx, targetURL, requestBody, opensslConfig)
	if err != nil {
		return nil, openSSLTLSMetadata{}, 0, err
	}

	rawResponse, firstByteTime, totalTime, opensslDiag, err := openSSLHTTPRequestRunner(ctx, connectAddress, serverName, opensslConfig, request)
	if opensslDiag != "" {
		logger.Debug("OpenSSL s_client interleaved output", "output", opensslDiag)
	}
	if firstByteTime > 0 {
		durationGaugeVec.WithLabelValues("processing").Add(firstByteTime.Seconds())
		if totalTime > firstByteTime {
			durationGaugeVec.WithLabelValues("transfer").Add((totalTime - firstByteTime).Seconds())
		}
	} else {
		durationGaugeVec.WithLabelValues("processing").Add(totalTime.Seconds())
	}
	if err != nil && len(rawResponse) == 0 {
		return nil, openSSLTLSMetadata{}, 0, fmt.Errorf("openssl request failed: %w; output=%s", err, opensslDiag)
	}

	resp, err := parseOpenSSLHTTPResponse(rawResponse, request)
	if err != nil {
		if opensslTLSCompleteButNoHTTP(rawResponse) {
			return nil, openSSLTLSMetadata{}, 0, fmt.Errorf("%w (peer closed without HTTP: check Host header and tls_config.server_name match the vhost you dial; openssl_http uses a second s_client for HTTP after the cert/metadata pass)", err)
		}
		return nil, openSSLTLSMetadata{}, 0, err
	}

	bodyBytes, err := processOpenSSLHTTPBody(ctx, resp, opensslConfig, logger)
	if err != nil {
		return nil, openSSLTLSMetadata{}, 0, err
	}

	return resp, metadata, bodyBytes, nil
}

func evaluateOpenSSLHTTPResponse(ctx context.Context, resp *http.Response, opensslConfig config.OpenSSLHTTPProbe, logger *slog.Logger, probeFailedDueToRegex, probeFailedDueToCEL prometheus.Gauge) bool {
	success := false

	logger.Info("Received HTTP response", "status_code", resp.StatusCode)
	if opensslConfig.AcceptAnyResponse {
		success = true
		logger.Info("Accepting any HTTP response due to accept_any_response setting", "status_code", resp.StatusCode)
	} else if len(opensslConfig.ValidStatusCodes) != 0 {
		for _, code := range opensslConfig.ValidStatusCodes {
			if resp.StatusCode == code {
				success = true
				break
			}
		}
		if !success {
			logger.Info("Invalid HTTP response status code", "status_code", resp.StatusCode, "valid_status_codes", fmt.Sprintf("%v", opensslConfig.ValidStatusCodes))
		}
	} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
		success = true
	} else {
		logger.Info("Invalid HTTP response status code, wanted 2xx", "status_code", resp.StatusCode)
	}

	if success && (len(opensslConfig.FailIfHeaderMatchesRegexp) > 0 || len(opensslConfig.FailIfHeaderNotMatchesRegexp) > 0) {
		success = matchRegularExpressionsOnHeaders(resp.Header, config.HTTPProbe{
			FailIfHeaderMatchesRegexp:    opensslConfig.FailIfHeaderMatchesRegexp,
			FailIfHeaderNotMatchesRegexp: opensslConfig.FailIfHeaderNotMatchesRegexp,
		}, logger)
		if success {
			probeFailedDueToRegex.Set(0)
		} else {
			probeFailedDueToRegex.Set(1)
		}
	}

	byteCounter := &byteCounter{ReadCloser: resp.Body}
	resp.Body = byteCounter

	if success && (len(opensslConfig.FailIfBodyMatchesRegexp) > 0 || len(opensslConfig.FailIfBodyNotMatchesRegexp) > 0) {
		success = matchRegularExpressions(byteCounter, config.HTTPProbe{
			FailIfBodyMatchesRegexp:    opensslConfig.FailIfBodyMatchesRegexp,
			FailIfBodyNotMatchesRegexp: opensslConfig.FailIfBodyNotMatchesRegexp,
		}, logger)
		if success {
			probeFailedDueToRegex.Set(0)
		} else {
			probeFailedDueToRegex.Set(1)
		}
	}

	if success && (opensslConfig.FailIfBodyJsonMatchesCEL != nil || opensslConfig.FailIfBodyJsonNotMatchesCEL != nil) {
		success = matchCELExpressions(ctx, byteCounter, config.HTTPProbe{
			FailIfBodyJsonMatchesCEL:    opensslConfig.FailIfBodyJsonMatchesCEL,
			FailIfBodyJsonNotMatchesCEL: opensslConfig.FailIfBodyJsonNotMatchesCEL,
		}, logger)
		if success {
			probeFailedDueToCEL.Set(0)
		} else {
			probeFailedDueToCEL.Set(1)
		}
	}

	if _, err := io.Copy(io.Discard, byteCounter); err != nil {
		logger.Info("Failed to read HTTP response body", "err", err)
		return false
	}

	if err := byteCounter.Close(); err != nil {
		logger.Info("Error while closing response from server", "error", err.Error())
	}

	return success
}

func processOpenSSLHTTPBody(_ context.Context, resp *http.Response, opensslConfig config.OpenSSLHTTPProbe, logger *slog.Logger) (int64, error) {
	if opensslConfig.Compression != "" {
		dec, err := getDecompressionReader(opensslConfig.Compression, resp.Body)
		if err != nil {
			return 0, err
		}
		if dec != nil {
			resp.Body = dec
		}
	}

	if opensslConfig.BodySizeLimit > 0 {
		resp.Body = http.MaxBytesReader(nil, resp.Body, int64(opensslConfig.BodySizeLimit))
	}

	bodyCopy, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Info("Failed to read HTTP response body", "err", err)
		return 0, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyCopy))
	return int64(len(bodyCopy)), nil
}

func shouldFollowOpenSSLHTTPRedirect(opensslConfig config.OpenSSLHTTPProbe, resp *http.Response, redirects int) bool {
	if !opensslConfig.FollowRedirects || redirects >= 10 {
		return false
	}
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	return resp.Header.Get("Location") != ""
}

func resolveOpenSSLHTTPRedirectTarget(currentTarget, location string) (string, error) {
	currentURL, err := url.Parse(currentTarget)
	if err != nil {
		return "", err
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return currentURL.ResolveReference(locationURL).String(), nil
}

func buildOpenSSLHTTPRequest(ctx context.Context, targetURL *url.URL, requestBody []byte, opensslConfig config.OpenSSLHTTPProbe) (*http.Request, error) {
	method := opensslConfig.Method
	if method == "" {
		method = "GET"
	}

	var body io.Reader
	if len(requestBody) > 0 {
		body = bytes.NewReader(requestBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Host = targetURL.Host
	for key, value := range opensslConfig.Headers {
		if textproto.CanonicalMIMEHeaderKey(key) == "Host" {
			req.Host = value
			continue
		}
		req.Header.Set(key, value)
	}
	if _, hasUserAgent := req.Header["User-Agent"]; !hasUserAgent {
		req.Header.Set("User-Agent", userAgentDefaultHeader)
	}
	req.Header.Set("Connection", "close")
	return req, nil
}

func loadOpenSSLHTTPRequestBody(opensslConfig config.OpenSSLHTTPProbe) ([]byte, error) {
	if opensslConfig.Body != "" {
		return []byte(opensslConfig.Body), nil
	}
	if opensslConfig.BodyFile != "" {
		return os.ReadFile(opensslConfig.BodyFile)
	}
	return nil, nil
}

func normalizeOpenSSLHTTPTarget(target string) string {
	if strings.HasPrefix(target, "https://") {
		return target
	}
	if strings.HasPrefix(target, "http://") {
		return "https://" + strings.TrimPrefix(target, "http://")
	}
	return "https://" + target
}

func getOpenSSLHTTPServerName(targetHost string, opensslConfig config.OpenSSLHTTPProbe) string {
	if opensslConfig.TLSConfig.ServerName != "" {
		return opensslConfig.TLSConfig.ServerName
	}
	for name, value := range opensslConfig.Headers {
		if textproto.CanonicalMIMEHeaderKey(name) == "Host" {
			return value
		}
	}
	return targetHost
}

func resolveOpenSSLHTTPProtocol(ctx context.Context, ipProtocol string, fallbackIPProtocol bool, target string) (ip *net.IPAddr, lookupTime float64, err error) {
	resolveStart := time.Now()
	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
	}()

	var fallbackProtocol string
	if ipProtocol == "ip6" || ipProtocol == "" {
		ipProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		ipProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	resolver := &net.Resolver{}
	if !fallbackIPProtocol {
		ips, err := resolver.LookupIP(ctx, ipProtocol, target)
		if err != nil {
			return nil, 0, err
		}
		if len(ips) == 0 {
			return nil, 0, fmt.Errorf("unable to find ip; no fallback")
		}
		return &net.IPAddr{IP: ips[0]}, lookupTime, nil
	}

	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil, 0, err
	}

	var fallback *net.IPAddr
	for _, resolved := range ips {
		switch ipProtocol {
		case "ip4":
			if resolved.IP.To4() != nil {
				return &resolved, lookupTime, nil
			}
			fallback = &resolved
		case "ip6":
			if resolved.IP.To4() == nil {
				return &resolved, lookupTime, nil
			}
			fallback = &resolved
		}
	}

	if fallback == nil {
		return nil, 0, fmt.Errorf("unable to find ip; no fallback")
	}

	_ = fallbackProtocol
	return fallback, lookupTime, nil
}

func fetchOpenSSLHTTPMetadata(ctx context.Context, connectAddress, serverName string, opensslConfig config.OpenSSLHTTPProbe) (openSSLTLSMetadata, error) {
	args := append(buildOpenSSLHTTPClientArgs(connectAddress, serverName, opensslConfig), "-showcerts")
	stdout, stderr, err := runOpenSSLHTTPCommand(ctx, opensslConfig.OpenSSLBinary, args, nil, openSSLHTTPEnv(opensslConfig))
	if err != nil {
		return openSSLTLSMetadata{}, fmt.Errorf("openssl metadata command failed: %w; stderr=%s", err, string(stderr))
	}

	output := string(append(stdout, stderr...))
	metadata := openSSLTLSMetadata{
		Version: parseOpenSSLNamedValue(output, []string{"Protocol version", "Protocol"}),
		Cipher:  parseOpenSSLNamedValue(output, []string{"Ciphersuite", "Cipher"}),
	}
	if metadata.Version == "" {
		metadata.Version = parseOpenSSLHandshakeVersion(output)
	}
	if metadata.Cipher == "" {
		metadata.Cipher = parseOpenSSLHandshakeCipher(output)
	}

	certs := extractPEMCertificates(output)
	if len(certs) == 0 {
		return metadata, nil
	}

	earliest := time.Time{}
	for i, certPEM := range certs {
		certInfo, err := parseOpenSSLCertificateInfo(ctx, opensslConfig, certPEM)
		if err != nil {
			return openSSLTLSMetadata{}, err
		}
		if earliest.IsZero() || certInfo.EarliestCertExpiry.Before(earliest) {
			earliest = certInfo.EarliestCertExpiry
		}
		if i == 0 {
			metadata.Fingerprint = certInfo.Fingerprint
			metadata.Subject = certInfo.Subject
			metadata.Issuer = certInfo.Issuer
			metadata.DNSNames = certInfo.DNSNames
			metadata.SerialNumber = certInfo.SerialNumber
		}
	}
	metadata.EarliestCertExpiry = earliest
	metadata.LastChainExpiry = earliest
	return metadata, nil
}

func executeOpenSSLHTTPRequest(ctx context.Context, connectAddress, serverName string, opensslConfig config.OpenSSLHTTPProbe, request *http.Request) ([]byte, time.Duration, time.Duration, string, error) {
	// No -quiet: some OpenSSL builds/FIPS hide application data or change buffering; trimToHTTPPayload skips TLS noise.
	args := append(buildOpenSSLHTTPClientArgs(connectAddress, serverName, opensslConfig), "-ign_eof")
	requestBytes, err := buildRawOpenSSLHTTPRequest(request)
	if err != nil {
		return nil, 0, 0, "", err
	}

	cmd := exec.CommandContext(ctx, opensslConfig.OpenSSLBinary, args...)
	cmd.Env = append(os.Environ(), openSSLHTTPEnv(opensslConfig)...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, 0, 0, "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, 0, "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, 0, 0, "", err
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, 0, 0, "", err
	}

	writeErr := make(chan error, 1)
	go func() {
		var werr error
		defer func() {
			_ = stdin.Close()
			writeErr <- werr
		}()
		var n int
		n, werr = stdin.Write(requestBytes)
		if werr != nil {
			werr = fmt.Errorf("openssl s_client stdin write: %w", werr)
			return
		}
		if n != len(requestBytes) {
			werr = fmt.Errorf("openssl s_client stdin short write: wrote %d of %d bytes", n, len(requestBytes))
		}
	}()

	capture := newOpenSSLInterleavedCapture(start)
	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)

	go func() {
		_, err := io.Copy(capture, stdout)
		stdoutDone <- err
	}()

	go func() {
		_, err := io.Copy(capture, stderr)
		stderrDone <- err
	}()

	waitErr := cmd.Wait()
	totalTime := time.Since(start)
	stdoutErr := <-stdoutDone
	stderrErr := <-stderrDone
	combined := capture.Bytes()
	firstByteTime := capture.firstByteElapsed()
	diag := string(combined)
	const diagMax = 16384
	if len(diag) > diagMax {
		diag = diag[:diagMax] + "...(truncated)"
	}
	if werr := <-writeErr; werr != nil {
		return combined, firstByteTime, totalTime, diag, werr
	}
	if stdoutErr != nil && !errors.Is(stdoutErr, io.EOF) {
		return combined, firstByteTime, totalTime, diag, stdoutErr
	}
	if stderrErr != nil && !errors.Is(stderrErr, io.EOF) {
		return combined, firstByteTime, totalTime, diag, stderrErr
	}
	return combined, firstByteTime, totalTime, diag, waitErr
}

func runOpenSSLHTTPCommand(ctx context.Context, binary string, args []string, input []byte, extraEnv []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func buildOpenSSLHTTPClientArgs(connectAddress, serverName string, opensslConfig config.OpenSSLHTTPProbe) []string {
	args := []string{"s_client", "-connect", connectAddress}
	if serverName != "" {
		args = append(args, "-servername", serverName)
	}
	if opensslConfig.TLSConfig.CAFile != "" {
		args = append(args, "-CAfile", opensslConfig.TLSConfig.CAFile)
	}
	if opensslConfig.TLSConfig.CertFile != "" {
		args = append(args, "-cert", opensslConfig.TLSConfig.CertFile)
	}
	if opensslConfig.TLSConfig.KeyFile != "" {
		args = append(args, "-key", opensslConfig.TLSConfig.KeyFile)
	}
	if opensslConfig.OpenSSLProviderPath != "" {
		args = append(args, "-provider-path", opensslConfig.OpenSSLProviderPath)
	}
	if opensslConfig.OpenSSLProvider != "" && opensslConfig.OpenSSLProvider != "default" {
		args = append(args, "-provider", "default")
	}
	if opensslConfig.OpenSSLProvider != "" {
		args = append(args, "-provider", opensslConfig.OpenSSLProvider)
	}
	if opensslConfig.OpenSSLEngine != "" {
		args = append(args, "-engine", opensslConfig.OpenSSLEngine)
	}
	if !opensslConfig.TLSConfig.InsecureSkipVerify {
		args = append(args, "-verify_return_error")
		if serverName != "" {
			args = append(args, "-verify_hostname", serverName)
		}
	}
	return args
}

func openSSLHTTPEnv(opensslConfig config.OpenSSLHTTPProbe) []string {
	if opensslConfig.OpenSSLProviderPath == "" {
		return nil
	}
	return []string{"OPENSSL_MODULES=" + opensslConfig.OpenSSLProviderPath}
}

func buildRawOpenSSLHTTPRequest(request *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	if err := request.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseOpenSSLHTTPResponse(rawResponse []byte, request *http.Request) (*http.Response, error) {
	if len(rawResponse) == 0 {
		return nil, errors.New("openssl s_client returned no bytes on stdout/stderr while reading the HTTP response (connection closed or no application data); increase module timeout or check server/WAF")
	}
	trimmed := trimToHTTPPayload(rawResponse)
	if !bytes.Contains(trimmed, []byte("HTTP/")) {
		const max = 512
		prev := rawResponse
		if len(prev) > max {
			prev = prev[:max]
		}
		return nil, fmt.Errorf("openssl output has no HTTP status line (no \"HTTP/\" marker); first %d bytes: %q", len(prev), string(prev))
	}
	resp, rerr := http.ReadResponse(bufio.NewReader(bytes.NewReader(trimmed)), request)
	if rerr != nil {
		const max = 512
		prev := trimmed
		if len(prev) > max {
			prev = prev[:max]
		}
		return nil, fmt.Errorf("parse HTTP response from openssl: %w; prefix: %q", rerr, string(prev))
	}
	return resp, nil
}

func trimToHTTPPayload(raw []byte) []byte {
	idx := bytes.Index(raw, []byte("HTTP/"))
	if idx == -1 {
		return raw
	}
	return raw[idx:]
}

// opensslTLSCompleteButNoHTTP detects s_client output where TLS came up but no HTTP status line followed
// (e.g. server closed after handshake — wrong Host/SNI vs vhost, WAF, or RST on second connection).
func opensslTLSCompleteButNoHTTP(b []byte) bool {
	if bytes.Contains(b, []byte("HTTP/")) {
		return false
	}
	return bytes.Contains(b, []byte("CONNECTED")) ||
		bytes.Contains(b, []byte("SSL-Session:")) ||
		bytes.Contains(b, []byte("New, TLS"))
}

// sanitizeProbeSSLChainLabel normalizes certificate strings for Prometheus label values
// (strip NUL/newlines; cap length on UTF-8 boundaries).
func sanitizeProbeSSLChainLabel(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	s = strings.ReplaceAll(s, "\x00", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= maxBytes {
		return s
	}
	b := []byte(s)
	for len(b) > maxBytes {
		_, sz := utf8.DecodeLastRune(b)
		if sz <= 0 {
			b = b[:len(b)-1]
			continue
		}
		b = b[:len(b)-sz]
	}
	return string(b)
}

func parseOpenSSLCertificateInfo(ctx context.Context, opensslConfig config.OpenSSLHTTPProbe, certPEM string) (openSSLTLSMetadata, error) {
	// -nameopt utf8: print DN in UTF-8 instead of OpenSSL's default ASCII escapes (\D0\B3… for Cyrillic).
	args := []string{"x509", "-noout", "-nameopt", "utf8", "-nameopt", "sep_comma_plus_space",
		"-enddate", "-subject", "-issuer", "-serial", "-fingerprint", "-sha256", "-ext", "subjectAltName"}
	if opensslConfig.OpenSSLProviderPath != "" {
		args = append(args, "-provider-path", opensslConfig.OpenSSLProviderPath)
	}
	if opensslConfig.OpenSSLProvider != "" && opensslConfig.OpenSSLProvider != "default" {
		args = append(args, "-provider", "default")
	}
	if opensslConfig.OpenSSLProvider != "" {
		args = append(args, "-provider", opensslConfig.OpenSSLProvider)
	}
	if opensslConfig.OpenSSLEngine != "" {
		args = append(args, "-engine", opensslConfig.OpenSSLEngine)
	}

	stdout, stderr, err := runOpenSSLHTTPCommand(ctx, opensslConfig.OpenSSLBinary, args, []byte(certPEM), openSSLHTTPEnv(opensslConfig))
	if err != nil {
		return openSSLTLSMetadata{}, fmt.Errorf("openssl x509 failed: %w; stderr=%s", err, string(stderr))
	}

	var metadata openSSLTLSMetadata
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "notAfter="):
			metadata.EarliestCertExpiry = parseOpenSSLTime(strings.TrimPrefix(line, "notAfter="))
		case strings.HasPrefix(line, "subject="):
			metadata.Subject = strings.TrimPrefix(line, "subject=")
		case strings.HasPrefix(line, "issuer="):
			metadata.Issuer = strings.TrimPrefix(line, "issuer=")
		case strings.HasPrefix(strings.ToUpper(line), "SHA256 FINGERPRINT="):
			value := strings.TrimPrefix(strings.ToUpper(line), "SHA256 FINGERPRINT=")
			metadata.Fingerprint = strings.ToLower(strings.ReplaceAll(value, ":", ""))
		case strings.HasPrefix(line, "serial="):
			metadata.SerialNumber = strings.ToLower(strings.TrimPrefix(line, "serial="))
		case strings.HasPrefix(line, "DNS:"):
			metadata.DNSNames = strings.ReplaceAll(line, "DNS:", "")
			metadata.DNSNames = strings.ReplaceAll(metadata.DNSNames, ", ", ",")
		}
	}

	if metadata.DNSNames == "" {
		metadata.DNSNames = parseOpenSSLSubjectAltNames(string(stdout))
	}
	metadata.LastChainExpiry = metadata.EarliestCertExpiry
	return metadata, nil
}

func parseOpenSSLTime(value string) time.Time {
	layouts := []string{
		"Jan _2 15:04:05 2006 MST",
		"Jan 2 15:04:05 2006 MST",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func parseOpenSSLSubjectAltNames(output string) string {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if strings.Contains(line, "Subject Alternative Name") && i+1 < len(lines) {
			value := strings.TrimSpace(lines[i+1])
			value = strings.ReplaceAll(value, "DNS:", "")
			value = strings.ReplaceAll(value, ", ", ",")
			return value
		}
	}
	return ""
}

func parseOpenSSLNamedValue(output string, keys []string) string {
	for _, line := range strings.Split(output, "\n") {
		for _, key := range keys {
			if strings.Contains(line, key+":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ""
}

func parseOpenSSLHandshakeVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "New, ") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func parseOpenSSLHandshakeCipher(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Cipher is ") {
			parts := strings.SplitN(line, "Cipher is ", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func extractPEMCertificates(output string) []string {
	var certs []string
	beginMarker := "-----BEGIN CERTIFICATE-----"
	endMarker := "-----END CERTIFICATE-----"
	for {
		begin := strings.Index(output, beginMarker)
		if begin == -1 {
			break
		}
		end := strings.Index(output[begin:], endMarker)
		if end == -1 {
			break
		}
		end += begin + len(endMarker)
		certs = append(certs, output[begin:end]+"\n")
		output = output[end:]
	}
	return certs
}
