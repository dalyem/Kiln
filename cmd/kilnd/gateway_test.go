package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayEnrollmentProofUsesSpecifiedLines(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := gatewayPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	proof := strings.Join([]string{"kiln-gateway-enroll-v1", "inst_1", "gw_1", "gen_1", "token_1", digest}, "\n")
	signature, err := gatewaySignature(key, proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256Bytes(proof)
	if !ecdsa.VerifyASN1(&key.PublicKey, digestBytes, decoded) {
		t.Fatal("proof signature did not verify")
	}
	if strings.HasSuffix(proof, "\n") {
		t.Fatal("proof must not have a final newline")
	}
}

func TestGatewayEnrollmentAndHeartbeatOverTLSPersistAcrossRestart(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	clientCAPEM := certificatePEM(t, clientCA.Certificate[0])
	serverCAPEM := certificatePEM(t, serverCA.Certificate[0])
	stateDir := t.TempDir()
	mustChmod(t, stateDir, 0700)
	serverCAPath := writePrivateTestFile(t, t.TempDir(), "server-ca.pem", serverCAPEM)
	clientCAPath := writePrivateTestFile(t, t.TempDir(), "client-ca.pem", clientCAPEM)
	tokenPath := writePrivateTestFile(t, t.TempDir(), "bootstrap-token", []byte("token_1\n"))

	var enrolled atomic.Bool
	var heartbeatCount atomic.Int64
	enrollment := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/gateway/enroll" {
			t.Fatalf("unexpected enrollment path %s", request.URL.Path)
		}
		var body struct {
			InstallationID string `json:"installationId"`
			ResourceID     string `json:"resourceId"`
			Generation     string `json:"generation"`
			Token          string `json:"token"`
			PublicKeyPEM   string `json:"publicKeyPem"`
			Signature      string `json:"signature"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.InstallationID != "inst_1" || body.ResourceID != "gw_1" || body.Generation != "gen_1" || body.Token != "token_1" {
			t.Fatalf("unexpected enrollment request: %#v", body)
		}
		block, _ := pem.Decode([]byte(body.PublicKeyPEM))
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		proof := strings.Join([]string{"kiln-gateway-enroll-v1", body.InstallationID, body.ResourceID, body.Generation, body.Token, sha256Hex(der)}, "\n")
		signature, err := base64.StdEncoding.DecodeString(body.Signature)
		if err != nil || !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), sha256Bytes(proof), signature) {
			t.Fatal("invalid enrollment proof")
		}
		expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
		leaf := issueGatewayLeaf(t, clientCA, publicKey, "inst_1", "gw_1", "gen_1", "device_1", expires)
		enrolled.Store(true)
		writeJSON(t, writer, gatewayEnrollmentResponse{DeviceID: "device_1", CertificatePEM: leaf, CertificateExpiresAt: expires.Format(time.RFC3339), NextSequence: 1})
	}))
	enrollment.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	enrollment.StartTLS()
	defer enrollment.Close()

	heartbeat := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
			t.Fatal("heartbeat did not carry a client certificate")
		}
		var body struct {
			DeviceID string `json:"deviceId"`
			Sequence int64  `json:"sequence"`
			Policy   string `json:"policy"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		expectedSequence := heartbeatCount.Load() + 1
		if body.DeviceID != "device_1" || body.Sequence != expectedSequence || body.Policy != "UNKNOWN" {
			t.Fatalf("unexpected heartbeat: %#v", body)
		}
		heartbeatCount.Add(1)
		writeJSON(t, writer, gatewayHeartbeatResponse{Accepted: true, NextSequence: expectedSequence + 1})
	}))
	heartbeat.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool(t, clientCAPEM)}
	heartbeat.StartTLS()
	defer heartbeat.Close()

	config := gatewayConfig{EnrollmentURL: enrollment.URL, HeartbeatURL: heartbeat.URL, ServerCAFile: serverCAPath, ClientCAFile: clientCAPath, InstallationID: "inst_1", ResourceID: "gw_1", Generation: "gen_1", BootstrapTokenFile: tokenPath, StateDir: stateDir}
	runtime, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ensureEnrolled(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !enrolled.Load() || heartbeatCount.Load() != 1 {
		t.Fatal("expected enrollment and heartbeat")
	}
	restarted, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.state.DeviceID != "device_1" || restarted.state.NextSequence != 2 {
		t.Fatalf("state was not persisted: %#v", restarted.state)
	}
	firstKey, _, err := gatewayPublicKey(runtime.key)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, _, err := gatewayPublicKey(restarted.key)
	if err != nil || firstKey != secondKey {
		t.Fatal("gateway key changed across restart")
	}
	if err := restarted.heartbeat(context.Background()); err != nil {
		t.Fatalf("restart did not restore the mTLS heartbeat client: %v", err)
	}
	if heartbeatCount.Load() != 2 {
		t.Fatal("expected heartbeat after restart")
	}
	// Renewal may be unavailable during a Core restart. The still-valid leaf must
	// keep sending heartbeats until its expiry.
	restarted.state.CertificateExpiresAt = time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if err := saveGatewayState(config.StateDir, restarted.state); err != nil {
		t.Fatal(err)
	}
	restarted.config.EnrollmentURL = "https://127.0.0.1:1"
	if err := restarted.ensureEnrolled(context.Background()); err == nil {
		t.Fatal("expected renewal listener outage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := restarted.run(ctx, time.Second); err != context.DeadlineExceeded {
		t.Fatalf("expected cancellation after fallback heartbeat, got %v", err)
	}
	if heartbeatCount.Load() != 3 {
		t.Fatal("valid certificate did not keep heartbeating through renewal outage")
	}
}

func TestGatewayRejectsBadCertificateAndRedirect(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	config := testGatewayConfig(t, serverCA.Certificate[0], clientCA.Certificate[0])
	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://example.invalid/captured", http.StatusFound)
	}))
	redirect.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	redirect.StartTLS()
	defer redirect.Close()
	config.EnrollmentURL = redirect.URL
	runtime, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ensureEnrolled(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := issueGatewayLeaf(t, clientCA, &otherKey.PublicKey, "inst_1", "gw_1", "gen_1", "device_1", time.Now().Add(time.Hour))
	if err := runtime.acceptCertificate(gatewayEnrollmentResponse{DeviceID: "device_1", CertificatePEM: certificate, CertificateExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), NextSequence: 1}); err == nil {
		t.Fatal("accepted a certificate for a different key")
	}
}

func TestGatewayRunHonorsCancellation(t *testing.T) {
	serverCA, _ := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	runtime, err := newGatewayRuntime(testGatewayConfig(t, serverCA.Certificate[0], clientCA.Certificate[0]))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.run(ctx, time.Millisecond); err != nil {
		t.Fatalf("expected clean shutdown, got %v", err)
	}
}

func TestGatewayConfigRejectsUnsafeEndpointsAndStatePermissions(t *testing.T) {
	config := gatewayConfig{EnrollmentURL: "https://token@example.test", HeartbeatURL: "https://example.test", ServerCAFile: "a", ClientCAFile: "b", InstallationID: "inst", ResourceID: "gw", Generation: "gen", BootstrapTokenFile: "token", StateDir: "state"}
	if err := config.validate(); err == nil {
		t.Fatal("accepted an endpoint with user info")
	}
	dir := t.TempDir()
	mustChmod(t, dir, 0755)
	if err := ensurePrivateDir(dir); err == nil {
		t.Fatal("accepted group-readable state directory")
	}
}

func TestGatewayStateDirectoryAllowsOneDaemonWriter(t *testing.T) {
	dir := t.TempDir()
	mustChmod(t, dir, 0700)
	first, err := acquireGatewayLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireGatewayLock(dir); err == nil {
		t.Fatal("allowed a second state writer")
	}
}

func TestGatewayKeyPersistsWhenEnrollmentDoesNotReturn(t *testing.T) {
	serverCA, _ := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	config := testGatewayConfig(t, serverCA.Certificate[0], clientCA.Certificate[0])
	config.EnrollmentURL = "https://127.0.0.1:1"
	first, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, _, err := gatewayPublicKey(first.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ensureEnrolled(context.Background()); err == nil {
		t.Fatal("unexpected enrollment success against an unavailable server")
	}
	second, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, _, err := gatewayPublicKey(second.key)
	if err != nil || firstKey != secondKey {
		t.Fatal("failed enrollment changed the persisted key")
	}
}

func TestGatewayLoadsAnExpiredIdentityForChallengeRecovery(t *testing.T) {
	serverCA, _ := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	config := testGatewayConfig(t, serverCA.Certificate[0], clientCA.Certificate[0])
	first, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	certificate := issueGatewayLeaf(t, clientCA, &first.key.PublicKey, "inst_1", "gw_1", "gen_1", "device_1", time.Now().Add(-30*time.Second))
	if err := saveGatewayState(config.StateDir, gatewayState{DeviceID: "device_1", CertificatePEM: certificate, CertificateExpiresAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), NextSequence: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := newGatewayRuntime(config); err != nil {
		t.Fatalf("expired identity must remain available for challenge recovery: %v", err)
	}
}

func TestCertificateStateWriteFailureDoesNotPublishCandidate(t *testing.T) {
	serverCA, _ := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	config := testGatewayConfig(t, serverCA.Certificate[0], clientCA.Certificate[0])
	runtime, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	oldClient := runtime.client
	runtime.state = gatewayState{DeviceID: "old_device", NextSequence: 7}
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	certificate := issueGatewayLeaf(t, clientCA, &runtime.key.PublicKey, "inst_1", "gw_1", "gen_1", "device_1", expires)
	runtime.config.StateDir = filepath.Join(t.TempDir(), "missing")
	err = runtime.acceptCertificate(gatewayEnrollmentResponse{DeviceID: "device_1", CertificatePEM: certificate, CertificateExpiresAt: expires.Format(time.RFC3339), NextSequence: 1})
	if err == nil {
		t.Fatal("expected state persistence failure")
	}
	if runtime.state.DeviceID != "old_device" || runtime.state.NextSequence != 7 || runtime.client != oldClient {
		t.Fatal("failed state write published a new identity")
	}
}

func TestRenewalRejectsAChangedDeviceID(t *testing.T) {
	serverCA, serverCert := testCAAndServerCert(t, "server-ca")
	clientCA, _ := testCAAndServerCert(t, "client-ca")
	config := testGatewayConfig(t, serverCA.Certificate[0], clientCA.Certificate[0])
	runtime, err := newGatewayRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	current := issueGatewayLeaf(t, clientCA, &runtime.key.PublicKey, "inst_1", "gw_1", "gen_1", "device_1", expires)
	runtime.state = gatewayState{DeviceID: "device_1", CertificatePEM: current, CertificateExpiresAt: expires.Format(time.RFC3339), NextSequence: 1}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/gateway/challenge":
			writeJSON(t, writer, gatewayChallengeResponse{ChallengeID: "challenge_1", Nonce: "nonce_1", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339)})
		case "/v1/gateway/renew":
			next := issueGatewayLeaf(t, clientCA, &runtime.key.PublicKey, "inst_1", "gw_1", "gen_1", "device_2", expires)
			writeJSON(t, writer, gatewayEnrollmentResponse{DeviceID: "device_2", CertificatePEM: next, CertificateExpiresAt: expires.Format(time.RFC3339), NextSequence: 2})
		default:
			t.Fatalf("unexpected route %s", request.URL.Path)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()
	runtime.config.EnrollmentURL = server.URL
	if err := runtime.renew(context.Background()); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("accepted a changed renewal device ID: %v", err)
	}
}

func TestServiceChecksShareOneDeadline(t *testing.T) {
	old := systemctlCommand
	defer func() { systemctlCommand = old }()
	systemctlCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestGatewayServiceCheckHelper", "--")
		command.Env = append(os.Environ(), "KILN_TEST_SLOW_SYSTEMCTL=1")
		return command
	}
	runtime := &gatewayRuntime{config: gatewayConfig{ServiceUnits: []string{"one.service", "two.service"}}}
	started := time.Now()
	if status := runtime.serviceStatus(context.Background()); status != "FAIL" {
		t.Fatalf("expected timeout failure, got %s", status)
	}
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("service checks exceeded one deadline: %s", elapsed)
	}
}

func TestGatewayServiceCheckHelper(t *testing.T) {
	if os.Getenv("KILN_TEST_SLOW_SYSTEMCTL") != "1" {
		return
	}
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

func testGatewayConfig(t *testing.T, serverCA, clientCA []byte) gatewayConfig {
	t.Helper()
	stateDir := t.TempDir()
	mustChmod(t, stateDir, 0700)
	return gatewayConfig{EnrollmentURL: "https://example.test", HeartbeatURL: "https://example.test", ServerCAFile: writePrivateTestFile(t, t.TempDir(), "server-ca.pem", certificatePEM(t, serverCA)), ClientCAFile: writePrivateTestFile(t, t.TempDir(), "client-ca.pem", certificatePEM(t, clientCA)), InstallationID: "inst_1", ResourceID: "gw_1", Generation: "gen_1", BootstrapTokenFile: writePrivateTestFile(t, t.TempDir(), "token", []byte("token_1")), StateDir: stateDir}
}

func testCAAndServerCert(t *testing.T, name string) (tls.Certificate, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{caDER}, PrivateKey: caKey}, tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
}

func issueGatewayLeaf(t *testing.T, issuer tls.Certificate, public any, installation, resource, generation, device string, expiry time.Time) string {
	t.Helper()
	issuerCertificate, err := x509.ParseCertificate(issuer.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("spiffe://kiln.dev/gateway/" + installation + "/" + resource + "/" + generation + "/" + device)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: device}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuerCertificate, public, issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(certificatePEM(t, der))
}

func certificatePEM(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func certPool(t *testing.T, contents []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		t.Fatal("could not parse test CA")
	}
	return pool
}

func writePrivateTestFile(t *testing.T, dir, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, body any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(body); err != nil {
		t.Fatal(err)
	}
}

func sha256Bytes(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestGatewayRejectsExhaustedSequenceBeforeMutatingState(t *testing.T) {
	runtime := &gatewayRuntime{config: gatewayConfig{StateDir: t.TempDir()}, state: gatewayState{DeviceID: "device_1", NextSequence: 2147483647}}
	if err := runtime.heartbeat(context.Background()); err == nil || err.Error() != "gateway heartbeat sequence exhausted" {
		t.Fatalf("expected sequence exhaustion, got %v", err)
	}
	if runtime.state.NextSequence != 2147483647 {
		t.Fatal("exhausted sequence changed before rejection")
	}
}

func TestGatewayServiceNamesCannotBecomeCommandOptions(t *testing.T) {
	original := systemctlCommand
	t.Cleanup(func() { systemctlCommand = original })
	systemctlCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name != "systemctl" || strings.Join(args, " ") != "is-active --quiet -- --version" {
			t.Fatalf("unit interpreted as an option: %s %v", name, args)
		}
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGatewayServiceCheckHelper$", "--")
	}
	runtime := &gatewayRuntime{config: gatewayConfig{ServiceUnits: []string{"--version"}}}
	if got := runtime.serviceStatus(context.Background()); got != "PASS" {
		t.Fatalf("unexpected status %s", got)
	}
}
