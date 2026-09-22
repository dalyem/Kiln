package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	probeMaxBody       = 1 << 20
	probeMaxChecks     = 8
	probeMaxTotal      = 30 * time.Second
	probeReportRetry   = 250 * time.Millisecond
	probeResponseDrain = 64 << 10
	probeCoreTimeout   = 10 * time.Second
)

type probeConfig struct {
	CoreURL      string `json:"coreUrl"`
	ServerCAFile string `json:"serverCaFile"`
	ProbeID      string `json:"probeId"`
	TokenFile    string `json:"tokenFile"`
}

type probePlanResponse struct {
	Plan       json.RawMessage `json:"plan"`
	PlanDigest string          `json:"planDigest"`
}

type probePlan struct {
	SchemaVersion            int               `json:"schemaVersion"`
	ProbeID                  string            `json:"probeId"`
	InstallationID           string            `json:"installationId"`
	GatewayID                string            `json:"gatewayId"`
	GatewayGeneration        string            `json:"gatewayGeneration"`
	GatewayConfigFingerprint string            `json:"gatewayConfigFingerprint"`
	ProfileID                string            `json:"profileId"`
	ProfileDigest            string            `json:"profileDigest"`
	ExpiresAt                string            `json:"expiresAt"`
	Checks                   []json.RawMessage `json:"checks"`
}

type probeCheckHeader struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	TimeoutMS int    `json:"timeoutMs"`
}

type probeCheck interface {
	id() string
	timeout() time.Duration
	run(context.Context) string
}

type dnsProbeCheck struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Hostname        string `json:"hostname"`
	ResolverAddress string `json:"resolverAddress"`
	ResolverPort    int    `json:"resolverPort"`
	TimeoutMS       int    `json:"timeoutMs"`
}

type httpsProbeCheck struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	URL            string `json:"url"`
	ExpectedStatus int    `json:"expectedStatus"`
	CAPEM          string `json:"caPem,omitempty"`
	TimeoutMS      int    `json:"timeoutMs"`
}

type tcpProbeCheck struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Expect    string `json:"expect"`
	TimeoutMS int    `json:"timeoutMs"`
}

type probeResult struct {
	ID         string `json:"id"`
	Code       string `json:"code"`
	DurationMS int64  `json:"durationMs"`
}

type probeReport struct {
	PlanDigest string        `json:"planDigest"`
	Results    []probeResult `json:"results"`
}

type probeRuntime struct {
	config probeConfig
	client *http.Client
	now    func() time.Time
}

func probeCommand(args []string) error {
	flags := flag.NewFlagSet("kilnd probe", flag.ContinueOnError)
	configPath := flags.String("config", "", "probe JSON configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *configPath == "" {
		return errors.New("usage: kilnd probe --config <path>")
	}
	config, err := readProbeConfig(*configPath)
	if err != nil {
		return errors.New("invalid probe configuration")
	}
	runtime, err := newProbeRuntime(config)
	if err != nil {
		return errors.New("invalid probe configuration")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = runtime.run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func readProbeConfig(path string) (probeConfig, error) {
	var config probeConfig
	file, err := openRegularFile(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, probeMaxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return config, errors.New("configuration has trailing data")
	}
	if err := config.validate(); err != nil {
		return config, err
	}
	return config, nil
}

func (config probeConfig) validate() error {
	if _, err := parseProbeBaseURL(config.CoreURL); err != nil {
		return err
	}
	if config.ServerCAFile == "" || config.TokenFile == "" || !validProbeID(config.ProbeID) {
		return errors.New("missing or invalid probe configuration")
	}
	return nil
}

func validProbeID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func parseProbeBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if len(raw) > 2048 || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.Opaque != "" {
		return nil, errors.New("invalid HTTPS endpoint")
	}
	return parsed, nil
}

func newProbeRuntime(config probeConfig) (*probeRuntime, error) {
	client, err := newProbeHTTPClient(config.ServerCAFile)
	if err != nil {
		return nil, err
	}
	return &probeRuntime{config: config, client: client, now: time.Now}, nil
}

func newProbeHTTPClient(serverCAFile string) (*http.Client, error) {
	roots, err := loadCertificatePool(serverCAFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true, Proxy: nil, MaxResponseHeaderBytes: probeResponseDrain, ResponseHeaderTimeout: probeCoreTimeout}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

func (runtime *probeRuntime) run(ctx context.Context) error {
	token, err := readProbeToken(runtime.config.TokenFile)
	if err != nil {
		return errors.New("could not read probe token")
	}
	response, err := runtime.fetchPlan(ctx, token)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	plan, checks, expiry, err := validateProbePlan(response.Plan, runtime.config.ProbeID, runtime.now())
	if err != nil {
		return errors.New("invalid probe plan")
	}
	if !validSHA256Digest(response.PlanDigest) {
		return errors.New("invalid probe plan")
	}
	checkDeadline := runtime.now().Add(probeMaxTotal)
	if expiry.Before(checkDeadline) {
		checkDeadline = expiry
	}
	results := executeProbeChecks(ctx, checks, checkDeadline)
	reportBytes, err := json.Marshal(probeReport{PlanDigest: response.PlanDigest, Results: results})
	if err != nil || len(reportBytes) > probeMaxBody {
		return errors.New("could not prepare probe report")
	}
	reportDeadline := runtime.now().Add(10 * time.Minute)
	if expiry.Before(reportDeadline) {
		reportDeadline = expiry
	}
	if err := runtime.submitReport(ctx, token, plan.ProbeID, reportBytes, reportDeadline); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func readProbeToken(path string) (string, error) {
	file, err := openPrivateRegularFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(contents) > 4096 {
		return "", errors.New("invalid probe token file")
	}
	token := strings.TrimSpace(string(contents))
	if !validGatewayID(token) {
		return "", errors.New("invalid probe token")
	}
	return token, nil
}

func (runtime *probeRuntime) fetchPlan(ctx context.Context, token string) (probePlanResponse, error) {
	var response probePlanResponse
	if err := runtime.requestJSON(ctx, http.MethodGet, "/v1/probes/"+url.PathEscape(runtime.config.ProbeID)+"/plan", token, nil, &response); err != nil {
		return response, errors.New("could not fetch probe plan")
	}
	return response, nil
}

func (runtime *probeRuntime) submitReport(ctx context.Context, token, probeID string, report []byte, deadline time.Time) error {
	for {
		requestContext, cancel := context.WithDeadline(ctx, deadline)
		var response struct {
			Accepted     bool   `json:"accepted"`
			ProbeID      string `json:"probeId"`
			ResultDigest string `json:"resultDigest"`
		}
		err := runtime.requestJSONBytes(requestContext, http.MethodPost, "/v1/probes/"+url.PathEscape(probeID)+"/result", token, report, &response)
		cancel()
		if err == nil {
			if !response.Accepted || response.ProbeID != probeID || !validSHA256Digest(response.ResultDigest) {
				return errors.New("probe report rejected")
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !isProbeRetryable(err) || !runtime.now().Before(deadline) {
			return errors.New("could not submit probe report")
		}
		wait := probeReportRetry
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			return errors.New("could not submit probe report")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

type probeHTTPError struct{ status int }

func (err probeHTTPError) Error() string { return "probe request failed" }

func isProbeRetryable(err error) bool {
	var status probeHTTPError
	if errors.As(err, &status) {
		return status.status >= 500 && status.status <= 599
	}
	return true
}

func (runtime *probeRuntime) requestJSON(ctx context.Context, method, path, token string, body any, result any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	return runtime.requestJSONBytes(ctx, method, path, token, payload, result)
}

func (runtime *probeRuntime) requestJSONBytes(ctx context.Context, method, path, token string, payload []byte, result any) error {
	base, err := parseProbeBaseURL(runtime.config.CoreURL)
	if err != nil {
		return err
	}
	base.Path = path
	if len(payload) > probeMaxBody {
		return errors.New("invalid probe request")
	}
	requestContext, cancel := context.WithTimeout(ctx, probeCoreTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, base.String(), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := runtime.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return probeHTTPError{status: response.StatusCode}
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, probeMaxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid probe response")
	}
	return nil
}

func validateProbePlan(raw json.RawMessage, expectedProbeID string, now time.Time) (probePlan, []probeCheck, time.Time, error) {
	var plan probePlan
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return plan, nil, time.Time{}, errors.New("invalid plan")
	}
	if plan.SchemaVersion != 1 || plan.ProbeID != expectedProbeID || !validProbeID(plan.ProbeID) || !validGatewayID(plan.InstallationID) || !validGatewayID(plan.GatewayID) || !validGatewayID(plan.GatewayGeneration) || !validOpaqueDigest(plan.GatewayConfigFingerprint) || !validProbeID(plan.ProfileID) || !validSHA256Digest(plan.ProfileDigest) || len(plan.Checks) == 0 || len(plan.Checks) > probeMaxChecks {
		return plan, nil, time.Time{}, errors.New("invalid plan")
	}
	expires, err := parseGatewayTimestamp(plan.ExpiresAt)
	if err != nil || !expires.After(now) {
		return plan, nil, time.Time{}, errors.New("expired plan")
	}
	checks := make([]probeCheck, 0, len(plan.Checks))
	seen := map[string]struct{}{}
	total := time.Duration(0)
	for _, rawCheck := range plan.Checks {
		check, err := parseProbeCheck(rawCheck)
		if err != nil {
			return plan, nil, time.Time{}, err
		}
		if _, ok := seen[check.id()]; ok {
			return plan, nil, time.Time{}, errors.New("duplicate probe check")
		}
		seen[check.id()] = struct{}{}
		total += check.timeout()
		if total > probeMaxTotal {
			return plan, nil, time.Time{}, errors.New("probe budget exceeded")
		}
		checks = append(checks, check)
	}
	return plan, checks, expires, nil
}

func validOpaqueDigest(value string) bool {
	if value == "" || len(value) > 256 || strings.IndexFunc(value, func(c rune) bool { return c < 0x21 || c > 0x7e }) >= 0 {
		return false
	}
	return true
}

func validSHA256Digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'f' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func parseProbeCheck(raw json.RawMessage) (probeCheck, error) {
	var header probeCheckHeader
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&header); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validProbeID(header.ID) || header.TimeoutMS < 100 || header.TimeoutMS > 5000 {
		return nil, errors.New("invalid probe check")
	}
	switch header.Kind {
	case "dns":
		var check dnsProbeCheck
		if err := strictDecodeProbeCheck(raw, &check); err != nil || check.ID != header.ID || check.Kind != header.Kind || check.TimeoutMS != header.TimeoutMS || !validDNSHostname(check.Hostname) || check.ResolverPort < 1 || check.ResolverPort > 65535 {
			return nil, errors.New("invalid DNS check")
		}
		resolver, err := netip.ParseAddr(check.ResolverAddress)
		if err != nil || !resolver.IsValid() {
			return nil, errors.New("invalid DNS check")
		}
		return check, nil
	case "https":
		var check httpsProbeCheck
		if err := strictDecodeProbeCheck(raw, &check); err != nil || check.ID != header.ID || check.Kind != header.Kind || check.TimeoutMS != header.TimeoutMS || check.ExpectedStatus < 200 || check.ExpectedStatus > 299 {
			return nil, errors.New("invalid HTTPS check")
		}
		if _, err := parseProbeHTTPSURL(check.URL); err != nil || !validCAPEM(check.CAPEM) {
			return nil, errors.New("invalid HTTPS check")
		}
		return check, nil
	case "tcp":
		var check tcpProbeCheck
		if err := strictDecodeProbeCheck(raw, &check); err != nil || check.ID != header.ID || check.Kind != header.Kind || check.TimeoutMS != header.TimeoutMS || check.Port < 1 || check.Port > 65535 || (check.Expect != "reachable" && check.Expect != "blocked") {
			return nil, errors.New("invalid TCP check")
		}
		address, err := netip.ParseAddr(check.Address)
		if err != nil || !address.IsValid() {
			return nil, errors.New("invalid TCP check")
		}
		return check, nil
	default:
		return nil, errors.New("unsupported probe check")
	}
}

func strictDecodeProbeCheck(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func validDNSHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func parseProbeHTTPSURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if len(raw) > 2048 || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("invalid HTTPS URL")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("invalid HTTPS URL")
		}
	}
	return parsed, nil
}

func validCAPEM(contents string) bool {
	if contents == "" {
		return true
	}
	if len(contents) > 16_384 {
		return false
	}
	rest := []byte(contents)
	count := 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return count == 1 && len(strings.TrimSpace(string(rest))) == 0
		}
		if block.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		if count > 1 {
			return false
		}
		rest = remaining
	}
}

func (check dnsProbeCheck) id() string { return check.ID }
func (check dnsProbeCheck) timeout() time.Duration {
	return time.Duration(check.TimeoutMS) * time.Millisecond
}

func (check dnsProbeCheck) run(ctx context.Context) string {
	answer, err := resolveDNSA(ctx, check.Hostname, check.ResolverAddress, check.ResolverPort)
	if isProbeTimeout(ctx, err) {
		return "TIMEOUT"
	}
	if err != nil {
		return "DNS_ERROR"
	}
	if answer {
		return "DNS_ANSWER"
	}
	return "DNS_EMPTY"
}

func (check httpsProbeCheck) id() string { return check.ID }
func (check httpsProbeCheck) timeout() time.Duration {
	return time.Duration(check.TimeoutMS) * time.Millisecond
}

func (check httpsProbeCheck) run(ctx context.Context) string {
	parsed, _ := parseProbeHTTPSURL(check.URL)
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if check.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(check.CAPEM)) {
		return "HTTPS_ERROR"
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, Proxy: nil, MaxResponseHeaderBytes: probeResponseDrain}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "HTTPS_ERROR"
	}
	response, err := client.Do(request)
	if isProbeTimeout(ctx, err) {
		return "TIMEOUT"
	}
	if err != nil {
		return "HTTPS_ERROR"
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		return "HTTPS_REDIRECT"
	}
	if response.StatusCode == check.ExpectedStatus {
		return "HTTPS_EXPECTED"
	}
	return "HTTPS_UNEXPECTED"
}

func (check tcpProbeCheck) id() string { return check.ID }
func (check tcpProbeCheck) timeout() time.Duration {
	return time.Duration(check.TimeoutMS) * time.Millisecond
}

func (check tcpProbeCheck) run(ctx context.Context) string {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(check.Address, fmt.Sprintf("%d", check.Port)))
	if isProbeTimeout(ctx, err) {
		return "TIMEOUT"
	}
	if err != nil {
		return "TCP_FAILED"
	}
	_ = connection.Close()
	return "TCP_CONNECTED"
}

func executeProbeChecks(ctx context.Context, checks []probeCheck, deadline time.Time) []probeResult {
	results := make([]probeResult, 0, len(checks))
	for _, check := range checks {
		started := time.Now()
		checkDeadline := started.Add(check.timeout())
		if deadline.Before(checkDeadline) {
			checkDeadline = deadline
		}
		checkContext, cancel := context.WithDeadline(ctx, checkDeadline)
		code := check.run(checkContext)
		cancel()
		duration := time.Since(started).Milliseconds()
		if duration < 0 {
			duration = 0
		}
		if duration > int64(probeMaxTotal/time.Millisecond) {
			duration = int64(probeMaxTotal / time.Millisecond)
		}
		results = append(results, probeResult{ID: check.id(), Code: code, DurationMS: duration})
	}
	return results
}

func isProbeTimeout(ctx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func resolveDNSA(ctx context.Context, hostname, resolverAddress string, resolverPort int) (bool, error) {
	packet, requestID, err := makeDNSQuestion(hostname)
	if err != nil {
		return false, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(resolverAddress, fmt.Sprintf("%d", resolverPort)))
	if err != nil {
		return false, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(packet); err != nil {
		return false, err
	}
	response := make([]byte, 4096)
	n, err := connection.Read(response)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, err
	}
	return parseDNSAResponse(response[:n], requestID)
}

func makeDNSQuestion(hostname string) ([]byte, uint16, error) {
	var randomBytes [2]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(randomBytes[:])
	packet := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split(hostname, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	return packet, id, nil
}

func parseDNSAResponse(packet []byte, requestID uint16) (bool, error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[0:2]) != requestID || packet[2]&0x80 == 0 || binary.BigEndian.Uint16(packet[2:4])&0x000f != 0 {
		return false, errors.New("invalid DNS response")
	}
	questions := int(binary.BigEndian.Uint16(packet[4:6]))
	answers := int(binary.BigEndian.Uint16(packet[6:8]))
	offset := 12
	for index := 0; index < questions; index++ {
		var err error
		offset, err = skipDNSName(packet, offset)
		if err != nil || offset+4 > len(packet) {
			return false, errors.New("invalid DNS response")
		}
		offset += 4
	}
	for index := 0; index < answers; index++ {
		var err error
		offset, err = skipDNSName(packet, offset)
		if err != nil || offset+10 > len(packet) {
			return false, errors.New("invalid DNS response")
		}
		kind := binary.BigEndian.Uint16(packet[offset : offset+2])
		class := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		length := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if length < 0 || offset+length > len(packet) {
			return false, errors.New("invalid DNS response")
		}
		if kind == 1 && class == 1 && length == 4 {
			return true, nil
		}
		offset += length
	}
	return false, nil
}

func skipDNSName(packet []byte, offset int) (int, error) {
	for jumps := 0; ; jumps++ {
		if offset >= len(packet) || jumps > len(packet) {
			return 0, errors.New("invalid DNS name")
		}
		length := int(packet[offset])
		if length == 0 {
			return offset + 1, nil
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return 0, errors.New("invalid DNS name")
			}
			return offset + 2, nil
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(packet) {
			return 0, errors.New("invalid DNS name")
		}
		offset += 1 + length
	}
}
