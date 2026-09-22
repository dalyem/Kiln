package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	probeTestPlanDigest    = strings.Repeat("a", 64)
	probeTestProfileDigest = strings.Repeat("b", 64)
	probeTestResultDigest  = strings.Repeat("c", 64)
)

func TestProbeExecutesLocalDNSHTTPSAndTCPAndReportsOnce(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "probe-core-ca")
	serverCAPath := writePrivateTestFile(t, t.TempDir(), "core-ca.pem", certificatePEM(t, serverCA.Certificate[0]))
	tokenPath := writePrivateTestFile(t, t.TempDir(), "probe-token", []byte("probe-secret\n"))

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	acceptedTCP := make(chan struct{}, 1)
	go func() {
		connection, err := tcpListener.Accept()
		if err == nil {
			_ = connection.Close()
			acceptedTCP <- struct{}{}
		}
	}()

	httpsTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	httpsTarget.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}
	httpsTarget.StartTLS()
	defer httpsTarget.Close()

	dnsConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConnection.Close()
	go respondDNSA(t, dnsConnection)

	plan := map[string]any{
		"schemaVersion": 1, "probeId": "probe_1", "installationId": "inst_1", "gatewayId": "gw_1", "gatewayGeneration": "gen_1", "gatewayConfigFingerprint": "config-sha256", "profileId": "profile_1", "profileDigest": probeTestProfileDigest, "expiresAt": time.Now().UTC().Add(time.Minute).Truncate(time.Second).Add(123 * time.Millisecond).Format(time.RFC3339Nano),
		"checks": []any{
			map[string]any{"id": "dns_1", "kind": "dns", "hostname": "example.test", "resolverAddress": "127.0.0.1", "resolverPort": dnsConnection.LocalAddr().(*net.UDPAddr).Port, "timeoutMs": 500},
			map[string]any{"id": "https_1", "kind": "https", "url": httpsTarget.URL, "expectedStatus": 204, "caPem": string(certificatePEM(t, serverCA.Certificate[0])), "timeoutMs": 500},
			map[string]any{"id": "tcp_1", "kind": "tcp", "address": "127.0.0.1", "port": tcpListener.Addr().(*net.TCPAddr).Port, "expect": "reachable", "timeoutMs": 500},
		},
	}
	var received probeReport
	var posts atomic.Int32
	core := probeTLSServer(t, serverCert, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer probe-secret" {
			t.Fatal("probe token did not use bearer authorization")
		}
		switch request.URL.Path {
		case "/v1/probes/probe_1/plan":
			writeJSON(t, writer, map[string]any{"plan": plan, "planDigest": probeTestPlanDigest})
		case "/v1/probes/probe_1/result":
			posts.Add(1)
			if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
				t.Fatal(err)
			}
			writeJSON(t, writer, map[string]any{"accepted": true, "probeId": "probe_1", "resultDigest": probeTestResultDigest})
		default:
			t.Fatalf("unexpected route %s", request.URL.Path)
		}
	})
	defer core.Close()
	runtime, err := newProbeRuntime(probeConfig{CoreURL: core.URL, ServerCAFile: serverCAPath, ProbeID: "probe_1", TokenFile: tokenPath})
	if err != nil {
		t.Fatal(err)
	}
	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := validateProbePlan(rawPlan, "probe_1", time.Now()); err != nil {
		t.Fatalf("fixture plan invalid: %v", err)
	}
	if err := runtime.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("expected one report, got %d", posts.Load())
	}
	select {
	case <-acceptedTCP:
	case <-time.After(time.Second):
		t.Fatal("TCP probe did not connect to local listener")
	}
	if received.PlanDigest != probeTestPlanDigest || len(received.Results) != 3 {
		t.Fatalf("unexpected report: %#v", received)
	}
	if received.Results[0].Code != "DNS_ANSWER" || received.Results[1].Code != "HTTPS_EXPECTED" || received.Results[2].Code != "TCP_CONNECTED" {
		t.Fatalf("unexpected result codes: %#v", received.Results)
	}
}

func TestProbeDNSDeadlineAndBlockedTCPProduceObservations(t *testing.T) {
	dnsConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConnection.Close()
	go func() {
		buffer := make([]byte, 512)
		_, _, _ = dnsConnection.ReadFrom(buffer)
	}()
	dns := dnsProbeCheck{ID: "dns", Hostname: "example.test", ResolverAddress: "127.0.0.1", ResolverPort: dnsConnection.LocalAddr().(*net.UDPAddr).Port, TimeoutMS: 100}
	dnsContext, cancelDNS := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelDNS()
	if got := dns.run(dnsContext); got != "TIMEOUT" {
		t.Fatalf("expected DNS timeout, got %s", got)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	blocked := tcpProbeCheck{ID: "blocked", Address: "127.0.0.1", Port: port, Expect: "blocked", TimeoutMS: 100}
	if got := blocked.run(context.Background()); got != "TCP_FAILED" {
		t.Fatalf("a blocked TCP target must be reported as an observation, got %s", got)
	}
}

func TestProbeHTTPSRedirectDoesNotFollow(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "redirect-ca")
	targetHit := atomic.Bool{}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHit.Store(true) }))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	redirect.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}
	redirect.StartTLS()
	defer redirect.Close()
	check := httpsProbeCheck{ID: "redirect", URL: redirect.URL, ExpectedStatus: 200, CAPEM: string(certificatePEM(t, serverCA.Certificate[0])), TimeoutMS: 500}
	if got := check.run(context.Background()); got != "HTTPS_REDIRECT" {
		t.Fatalf("expected redirect observation, got %s", got)
	}
	if targetHit.Load() {
		t.Fatal("HTTPS probe followed a redirect")
	}
}

func TestProbeHTTPSDoesNotWaitForAResponseBody(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "stalled-body-ca")
	release := make(chan struct{})
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		<-release
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}
	target.StartTLS()
	defer func() { close(release); target.Close() }()
	check := httpsProbeCheck{ID: "stalled", URL: target.URL, ExpectedStatus: http.StatusOK, CAPEM: string(certificatePEM(t, serverCA.Certificate[0])), TimeoutMS: 100}
	started := time.Now()
	if got := check.run(context.Background()); got != "HTTPS_EXPECTED" {
		t.Fatalf("expected header-only HTTPS success, got %s", got)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("HTTPS probe waited for a response body: %s", elapsed)
	}
}

func TestProbeRejectsCertificateBundlesInHTTPSPlan(t *testing.T) {
	ca, _ := testCAAndServerCert(t, "probe-bundle-ca")
	single := string(certificatePEM(t, ca.Certificate[0]))
	if !validCAPEM(single) {
		t.Fatal("expected one certificate to be accepted")
	}
	if validCAPEM(single + single) {
		t.Fatal("accepted a certificate bundle")
	}
}

func TestProbeRejectsBadTokenUnsafePlanAndExpiredPlanBeforeChecks(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "probe-core-ca")
	serverCAPath := writePrivateTestFile(t, t.TempDir(), "core-ca.pem", certificatePEM(t, serverCA.Certificate[0]))
	unsafeToken := writePrivateTestFile(t, t.TempDir(), "token", []byte("secret"))
	if err := os.Chmod(unsafeToken, 0644); err != nil {
		t.Fatal(err)
	}
	runtime, err := newProbeRuntime(probeConfig{CoreURL: "https://example.test", ServerCAFile: serverCAPath, ProbeID: "probe_1", TokenFile: unsafeToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.run(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe token file must fail without disclosing contents: %v", err)
	}

	validToken := writePrivateTestFile(t, t.TempDir(), "token", []byte("secret"))
	checksStarted := atomic.Int32{}
	plan := map[string]any{
		"schemaVersion": 1, "probeId": "probe_1", "installationId": "inst_1", "gatewayId": "gw_1", "gatewayGeneration": "gen_1", "gatewayConfigFingerprint": "config", "profileId": "profile", "profileDigest": probeTestProfileDigest, "expiresAt": time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		"checks": []any{map[string]any{"id": "tcp", "kind": "tcp", "address": "127.0.0.1", "port": 1, "expect": "reachable", "timeoutMs": 100}},
	}
	core := probeTLSServer(t, serverCert, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/probes/probe_1/plan" {
			writeJSON(t, writer, map[string]any{"plan": plan, "planDigest": probeTestPlanDigest})
			return
		}
		checksStarted.Add(1)
		t.Fatal("expired plan submitted a report")
	})
	defer core.Close()
	runtime, err = newProbeRuntime(probeConfig{CoreURL: core.URL, ServerCAFile: serverCAPath, ProbeID: "probe_1", TokenFile: validToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.run(context.Background()); err == nil || err.Error() != "invalid probe plan" {
		t.Fatalf("expired plan must not execute checks: %v", err)
	}
	if checksStarted.Load() != 0 {
		t.Fatal("expired plan ran a network operation")
	}

	invalid := []byte(`{"schemaVersion":1,"probeId":"probe_1","installationId":"inst","gatewayId":"gw","gatewayGeneration":"gen","gatewayConfigFingerprint":"x","profileId":"profile","profileDigest":"x","expiresAt":"2030-01-01T00:00:00Z","checks":[{"id":"dns","kind":"dns","hostname":"example.test","resolverAddress":"not-an-ip","resolverPort":53,"timeoutMs":100}]}`)
	if _, _, _, err := validateProbePlan(invalid, "probe_1", time.Now()); err == nil {
		t.Fatal("accepted an invalid DNS resolver")
	}
	unknownField := []byte(`{"schemaVersion":1,"probeId":"probe_1","installationId":"inst","gatewayId":"gw","gatewayGeneration":"gen","gatewayConfigFingerprint":"x","profileId":"profile","profileDigest":"x","expiresAt":"2030-01-01T00:00:00Z","checks":[{"id":"tcp","kind":"tcp","address":"127.0.0.1","port":443,"expect":"reachable","timeoutMs":100,"unexpected":true}]}`)
	if _, _, _, err := validateProbePlan(unknownField, "probe_1", time.Now()); err == nil {
		t.Fatal("accepted an unknown check field")
	}
	if _, err := parseProbeHTTPSURL("https://example.test:http"); err == nil {
		t.Fatal("accepted a named HTTPS service port")
	}
}

func TestProbeRejectsCoreWithDifferentRoot(t *testing.T) {
	trustedCA, _ := testCAAndServerCert(t, "trusted-ca")
	_, serverCert := testCAAndServerCert(t, "other-ca")
	core := probeTLSServer(t, serverCert, func(writer http.ResponseWriter, request *http.Request) {
		t.Fatal("untrusted server received a request")
	})
	defer core.Close()
	runtime, err := newProbeRuntime(probeConfig{CoreURL: core.URL, ServerCAFile: writePrivateTestFile(t, t.TempDir(), "trusted.pem", certificatePEM(t, trustedCA.Certificate[0])), ProbeID: "probe_1", TokenFile: writePrivateTestFile(t, t.TempDir(), "token", []byte("secret"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.fetchPlan(context.Background(), "secret"); err == nil {
		t.Fatal("probe trusted a Core endpoint signed by a different CA")
	}
}

func TestProbePlanFetchHonorsCallerDeadline(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "slow-core-ca")
	started := make(chan struct{})
	core := probeTLSServer(t, serverCert, func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	})
	defer core.Close()
	runtime, err := newProbeRuntime(probeConfig{CoreURL: core.URL, ServerCAFile: writePrivateTestFile(t, t.TempDir(), "core.pem", certificatePEM(t, serverCA.Certificate[0])), ProbeID: "probe_1", TokenFile: writePrivateTestFile(t, t.TempDir(), "token", []byte("secret"))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	if _, err := runtime.fetchPlan(ctx, "secret"); err == nil {
		t.Fatal("plan fetch hung on a Core endpoint that never sent headers")
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("plan fetch ignored its deadline: %s", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("test Core did not receive the plan request")
	}
}

func TestProbeRetriesTheSameReportBytes(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "retry-core-ca")
	var attempts atomic.Int32
	var firstBody string
	core := probeTLSServer(t, serverCert, func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if attempt := attempts.Add(1); attempt == 1 {
			firstBody = string(body)
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if string(body) != firstBody {
			t.Fatal("probe changed report bytes while retrying")
		}
		writeJSON(t, writer, map[string]any{"accepted": true, "probeId": "probe_1", "resultDigest": probeTestResultDigest})
	})
	defer core.Close()
	runtime, err := newProbeRuntime(probeConfig{CoreURL: core.URL, ServerCAFile: writePrivateTestFile(t, t.TempDir(), "core.pem", certificatePEM(t, serverCA.Certificate[0])), ProbeID: "probe_1", TokenFile: writePrivateTestFile(t, t.TempDir(), "token", []byte("secret"))})
	if err != nil {
		t.Fatal(err)
	}
	report := []byte(`{"planDigest":"` + probeTestPlanDigest + `","results":[{"id":"tcp","code":"TCP_FAILED","durationMs":0}]}`)
	if err := runtime.submitReport(context.Background(), "secret", "probe_1", report, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected exactly two report attempts, got %d", attempts.Load())
	}
}

func TestProbeRunReturnsCancellationWithoutReporting(t *testing.T) {
	serverCA, _ := testCAAndServerCert(t, "cancel-core-ca")
	runtime, err := newProbeRuntime(probeConfig{CoreURL: "https://127.0.0.1:1", ServerCAFile: writePrivateTestFile(t, t.TempDir(), "core.pem", certificatePEM(t, serverCA.Certificate[0])), ProbeID: "probe_1", TokenFile: writePrivateTestFile(t, t.TempDir(), "token", []byte("secret"))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.run(ctx); err != context.Canceled {
		t.Fatalf("expected clean cancellation, got %v", err)
	}
}

func probeTLSServer(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	return server
}

func respondDNSA(t *testing.T, connection net.PacketConn) {
	t.Helper()
	buffer := make([]byte, 512)
	count, remote, err := connection.ReadFrom(buffer)
	if err != nil {
		return
	}
	if count < 12 {
		t.Error("short DNS question")
		return
	}
	questionEnd := 12
	for questionEnd < count && buffer[questionEnd] != 0 {
		questionEnd += int(buffer[questionEnd]) + 1
	}
	questionEnd += 5
	if questionEnd > count {
		t.Error("invalid DNS question")
		return
	}
	response := append([]byte(nil), buffer[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1)
	_, _ = connection.WriteTo(response, remote)
}
