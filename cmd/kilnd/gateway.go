package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	gatewayRequestTimeout = 10 * time.Second
	gatewayHeartbeatEvery = 5 * time.Second
	gatewayRenewBefore    = 12 * time.Hour
	maxGatewayBody        = 1 << 20
	maxGatewaySequence    = int64(2147483646)
	maxSafeSequence       = maxGatewaySequence + 1
)

var systemctlCommand = exec.CommandContext

type gatewayConfig struct {
	EnrollmentURL      string   `json:"enrollmentUrl"`
	HeartbeatURL       string   `json:"heartbeatUrl"`
	ServerCAFile       string   `json:"serverCaFile"`
	ClientCAFile       string   `json:"clientCaFile"`
	InstallationID     string   `json:"installationId"`
	ResourceID         string   `json:"resourceId"`
	Generation         string   `json:"generation"`
	BootstrapTokenFile string   `json:"bootstrapTokenFile"`
	StateDir           string   `json:"stateDir"`
	ServiceUnits       []string `json:"serviceUnits,omitempty"`
}

type gatewayState struct {
	DeviceID             string `json:"deviceId"`
	CertificatePEM       string `json:"certificatePem"`
	CertificateExpiresAt string `json:"certificateExpiresAt"`
	NextSequence         int64  `json:"nextSequence"`
}

type gatewayEnrollmentResponse struct {
	DeviceID             string `json:"deviceId"`
	CertificatePEM       string `json:"certificatePem"`
	CertificateExpiresAt string `json:"certificateExpiresAt"`
	NextSequence         int64  `json:"nextSequence"`
}

type gatewayChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	ExpiresAt   string `json:"expiresAt"`
}

type gatewayHeartbeatResponse struct {
	Accepted     bool  `json:"accepted"`
	NextSequence int64 `json:"nextSequence"`
}

type gatewayRuntime struct {
	config gatewayConfig
	key    *ecdsa.PrivateKey
	state  gatewayState
	now    func() time.Time
	client *http.Client
	mu     sync.Mutex
}

func gatewayCommand(args []string) error {
	flags := flag.NewFlagSet("kilnd gateway", flag.ContinueOnError)
	configPath := flags.String("config", "", "gateway JSON configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *configPath == "" {
		return errors.New("usage: kilnd gateway --config <path>")
	}
	config, err := readGatewayConfig(*configPath)
	if err != nil {
		return errors.New("invalid gateway configuration")
	}
	if err := ensurePrivateDir(config.StateDir); err != nil {
		return errors.New("could not initialize gateway identity")
	}
	lock, err := acquireGatewayLock(config.StateDir)
	if err != nil {
		return errors.New("could not initialize gateway identity")
	}
	defer lock.Close()
	runtime, err := newGatewayRuntime(config)
	if err != nil {
		return errors.New("could not initialize gateway identity")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runtime.run(ctx, gatewayHeartbeatEvery)
}

func readGatewayConfig(path string) (gatewayConfig, error) {
	var config gatewayConfig
	file, err := openRegularFile(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxGatewayBody))
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

func (config gatewayConfig) validate() error {
	for _, value := range []string{config.ServerCAFile, config.ClientCAFile, config.BootstrapTokenFile, config.StateDir} {
		if value == "" || strings.ContainsRune(value, 0) {
			return errors.New("missing path")
		}
	}
	for _, value := range []string{config.InstallationID, config.ResourceID, config.Generation} {
		if !validGatewayID(value) {
			return errors.New("invalid identifier")
		}
	}
	if _, err := parseGatewayBaseURL(config.EnrollmentURL); err != nil {
		return err
	}
	if _, err := parseGatewayBaseURL(config.HeartbeatURL); err != nil {
		return err
	}
	if len(config.ServiceUnits) > 64 {
		return errors.New("too many service units")
	}
	for _, unit := range config.ServiceUnits {
		if !validSystemdUnit(unit) {
			return errors.New("invalid service unit")
		}
	}
	return nil
}

func validGatewayID(value string) bool {
	if value == "" || len(value) > 200 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f || character == '\n' || character == '\r' {
			return false
		}
	}
	return true
}

func validSystemdUnit(value string) bool {
	if value == "" || len(value) > 200 || strings.Contains(value, "/") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._@:-", character)) {
			return false
		}
	}
	return true
}

func parseGatewayBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.Opaque != "" {
		return nil, errors.New("invalid HTTPS endpoint")
	}
	return parsed, nil
}

func newGatewayRuntime(config gatewayConfig) (*gatewayRuntime, error) {
	if err := ensurePrivateDir(config.StateDir); err != nil {
		return nil, err
	}
	key, err := loadOrCreateGatewayKey(config.StateDir)
	if err != nil {
		return nil, err
	}
	state, err := loadGatewayState(config.StateDir)
	if err != nil {
		return nil, err
	}
	if state.DeviceID != "" {
		if _, err := verifyGatewayCertificateBinding(config, key, state.DeviceID, state.CertificatePEM); err != nil {
			return nil, err
		}
	}
	client, err := newGatewayHTTPClient(config.ServerCAFile, nil)
	if err != nil {
		return nil, err
	}
	runtime := &gatewayRuntime{config: config, key: key, state: state, now: time.Now, client: client}
	if state.DeviceID != "" {
		if err := runtime.resetHeartbeatClient(); err != nil {
			return nil, err
		}
	}
	return runtime, nil
}

func (runtime *gatewayRuntime) run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("invalid heartbeat interval")
	}
	lastStatus := ""
	for {
		err := runtime.ensureEnrolled(ctx)
		usable := runtime.hasUsableCertificate()
		if err != nil {
			status := "gateway enrollment retrying"
			if runtime.state.DeviceID != "" {
				status = "gateway renewal retrying"
			}
			runtime.logTransition(&lastStatus, status)
		}
		if err == nil || usable {
			if err := runtime.heartbeat(ctx); err == nil {
				runtime.logTransition(&lastStatus, "gateway connected")
				if err := waitGateway(ctx, interval); err != nil {
					if errors.Is(err, context.Canceled) {
						fmt.Fprintln(os.Stderr, "kilnd gateway stopped")
						return nil
					}
					return err
				}
				continue
			}
			runtime.logTransition(&lastStatus, "gateway heartbeat unavailable")
		}
		if err := waitGateway(ctx, gatewayBackoff()); err != nil {
			if errors.Is(err, context.Canceled) {
				fmt.Fprintln(os.Stderr, "kilnd gateway stopped")
				return nil
			}
			return err
		}
	}
}

func (runtime *gatewayRuntime) logTransition(last *string, status string) {
	if *last != status {
		fmt.Fprintln(os.Stderr, status)
		*last = status
	}
}

func (runtime *gatewayRuntime) hasUsableCertificate() bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	expires, err := parseWholeGatewayTimestamp(runtime.state.CertificateExpiresAt)
	return runtime.state.DeviceID != "" && err == nil && expires.After(runtime.now())
}

func waitGateway(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func gatewayBackoff() time.Duration {
	// The jitter avoids a synchronized reconnect surge after a Core restart.
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 2 * time.Second
	}
	return 1*time.Second + time.Duration((int(value[0])<<8|int(value[1]))%1000)*time.Millisecond
}

func (runtime *gatewayRuntime) ensureEnrolled(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.state.DeviceID == "" {
		return runtime.enroll(ctx)
	}
	expires, err := parseWholeGatewayTimestamp(runtime.state.CertificateExpiresAt)
	if err != nil || !expires.After(runtime.now()) {
		return runtime.renew(ctx)
	}
	if expires.Sub(runtime.now()) <= gatewayRenewBefore {
		return runtime.renew(ctx)
	}
	return nil
}

func (runtime *gatewayRuntime) enroll(ctx context.Context) error {
	token, err := readBootstrapToken(runtime.config.BootstrapTokenFile)
	if err != nil {
		return err
	}
	publicPEM, digest, err := gatewayPublicKey(runtime.key)
	if err != nil {
		return err
	}
	proof := strings.Join([]string{"kiln-gateway-enroll-v1", runtime.config.InstallationID, runtime.config.ResourceID, runtime.config.Generation, token, digest}, "\n")
	signature, err := gatewaySignature(runtime.key, proof)
	if err != nil {
		return err
	}
	response := gatewayEnrollmentResponse{}
	if err := runtime.postJSON(ctx, runtime.config.EnrollmentURL, "/v1/gateway/enroll", map[string]string{
		"installationId": runtime.config.InstallationID, "resourceId": runtime.config.ResourceID, "generation": runtime.config.Generation,
		"token": token, "publicKeyPem": publicPEM, "signature": signature,
	}, &response, nil); err != nil {
		return err
	}
	return runtime.acceptCertificate(response)
}

func (runtime *gatewayRuntime) renew(ctx context.Context) error {
	challenge := gatewayChallengeResponse{}
	if err := runtime.postJSON(ctx, runtime.config.EnrollmentURL, "/v1/gateway/challenge", map[string]string{"deviceId": runtime.state.DeviceID}, &challenge, nil); err != nil {
		return err
	}
	if !validGatewayID(challenge.ChallengeID) || !validGatewayID(challenge.Nonce) {
		return errors.New("invalid challenge")
	}
	challengeExpiry, err := parseGatewayTimestamp(challenge.ExpiresAt)
	if err != nil || !challengeExpiry.After(runtime.now()) {
		return errors.New("expired challenge")
	}
	proof := strings.Join([]string{"kiln-gateway-renew-v1", runtime.config.InstallationID, runtime.config.ResourceID, runtime.config.Generation, runtime.state.DeviceID, challenge.ChallengeID, challenge.Nonce}, "\n")
	signature, err := gatewaySignature(runtime.key, proof)
	if err != nil {
		return err
	}
	response := gatewayEnrollmentResponse{}
	if err := runtime.postJSON(ctx, runtime.config.EnrollmentURL, "/v1/gateway/renew", map[string]string{
		"deviceId": runtime.state.DeviceID, "challengeId": challenge.ChallengeID, "nonce": challenge.Nonce, "signature": signature,
	}, &response, nil); err != nil {
		return err
	}
	if response.DeviceID != runtime.state.DeviceID {
		return errors.New("renewal identity mismatch")
	}
	return runtime.acceptCertificate(response)
}

func (runtime *gatewayRuntime) acceptCertificate(response gatewayEnrollmentResponse) error {
	if !validGatewayID(response.DeviceID) || response.NextSequence < 1 || response.NextSequence > maxSafeSequence {
		return errors.New("invalid certificate response")
	}
	expires, err := parseWholeGatewayTimestamp(response.CertificateExpiresAt)
	if err != nil || !expires.After(runtime.now()) {
		return errors.New("invalid certificate expiry")
	}
	certificate, err := parseGatewayCertificate(response.CertificatePEM)
	if err != nil || !certificate.NotAfter.Equal(expires) {
		return errors.New("invalid certificate expiry")
	}
	if err := verifyGatewayCertificate(runtime.config, runtime.key, response.DeviceID, response.CertificatePEM, runtime.now()); err != nil {
		return err
	}
	candidate := gatewayState{DeviceID: response.DeviceID, CertificatePEM: response.CertificatePEM, CertificateExpiresAt: response.CertificateExpiresAt, NextSequence: response.NextSequence}
	tlsCertificate, err := gatewayTLSCertificate(candidate.CertificatePEM, runtime.key)
	if err != nil {
		return err
	}
	client, err := newGatewayHTTPClient(runtime.config.ServerCAFile, tlsCertificate)
	if err != nil {
		return err
	}
	if err := saveGatewayState(runtime.config.StateDir, candidate); err != nil {
		return err
	}
	runtime.state = candidate
	runtime.client = client
	return nil
}

func (runtime *gatewayRuntime) resetHeartbeatClient() error {
	tlsCertificate, err := gatewayTLSCertificate(runtime.state.CertificatePEM, runtime.key)
	if err != nil {
		return err
	}
	client, err := newGatewayHTTPClient(runtime.config.ServerCAFile, tlsCertificate)
	if err != nil {
		return err
	}
	runtime.client = client
	return nil
}

func gatewayTLSCertificate(certificatePEM string, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), gatewayPrivateKeyPEM(key))
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

func (runtime *gatewayRuntime) heartbeat(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.state.DeviceID == "" || runtime.state.NextSequence < 1 {
		return errors.New("missing gateway identity")
	}
	if runtime.state.NextSequence > maxGatewaySequence {
		return errors.New("gateway heartbeat sequence exhausted")
	}
	sequence := runtime.state.NextSequence
	// Reserve the next value before the request. A crash after an accepted request
	// can then only skip a sequence, never replay an already accepted sample.
	runtime.state.NextSequence++
	if err := saveGatewayState(runtime.config.StateDir, runtime.state); err != nil {
		return err
	}
	services := runtime.serviceStatus(ctx)
	response := gatewayHeartbeatResponse{}
	if err := runtime.postJSON(ctx, runtime.config.HeartbeatURL, "/v1/gateway/heartbeat", map[string]any{
		"deviceId": runtime.state.DeviceID, "sequence": sequence, "services": services, "policy": "UNKNOWN", "reservation": "UNKNOWN",
	}, &response, runtime.client); err != nil {
		return err
	}
	if !response.Accepted || response.NextSequence < runtime.state.NextSequence || response.NextSequence > maxSafeSequence {
		return errors.New("heartbeat rejected")
	}
	runtime.state.NextSequence = response.NextSequence
	return saveGatewayState(runtime.config.StateDir, runtime.state)
}

func (runtime *gatewayRuntime) serviceStatus(ctx context.Context) string {
	if len(runtime.config.ServiceUnits) == 0 {
		return "UNKNOWN"
	}
	checksContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, unit := range runtime.config.ServiceUnits {
		err := systemctlCommand(checksContext, "systemctl", "is-active", "--quiet", "--", unit).Run()
		if err != nil {
			return "FAIL"
		}
	}
	return "PASS"
}

func (runtime *gatewayRuntime) postJSON(ctx context.Context, base, path string, requestBody any, responseBody any, override *http.Client) error {
	parsed, err := parseGatewayBaseURL(base)
	if err != nil {
		return err
	}
	parsed.Path = path
	payload, err := json.Marshal(requestBody)
	if err != nil || len(payload) > maxGatewayBody {
		return errors.New("invalid request")
	}
	requestContext, cancel := context.WithTimeout(ctx, gatewayRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, parsed.String(), strings.NewReader(string(payload)))
	if err != nil {
		return errors.New("could not create request")
	}
	request.Header.Set("Content-Type", "application/json")
	client := runtime.client
	if override != nil {
		client = override
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("gateway request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("gateway request failed with HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxGatewayBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(responseBody); err != nil {
		return errors.New("invalid gateway response")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid gateway response")
	}
	return nil
}

func gatewayPublicKey(key *ecdsa.PrivateKey) (string, string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), hex.EncodeToString(digest[:]), nil
}

func gatewaySignature(key *ecdsa.PrivateKey, text string) (string, error) {
	digest := sha256.Sum256([]byte(text))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func verifyGatewayCertificate(config gatewayConfig, key *ecdsa.PrivateKey, deviceID, certificatePEM string, now time.Time) error {
	certificate, err := verifyGatewayCertificateBinding(config, key, deviceID, certificatePEM)
	if err != nil {
		return err
	}
	if !certificate.NotAfter.After(now) {
		return errors.New("expired client certificate")
	}
	roots, err := loadCertificatePool(config.ClientCAFile)
	if err != nil {
		return err
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("untrusted client certificate")
	}
	return nil
}

func verifyGatewayCertificateBinding(config gatewayConfig, key *ecdsa.PrivateKey, deviceID, certificatePEM string) (*x509.Certificate, error) {
	certificate, err := parseGatewayCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	roots, err := loadCertificatePool(config.ClientCAFile)
	if err != nil {
		return nil, err
	}
	verificationTime := certificate.NotBefore.Add(time.Second)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: verificationTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, errors.New("untrusted client certificate")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	certificateDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil || string(publicDER) != string(certificateDER) {
		return nil, errors.New("client certificate key mismatch")
	}
	expected := "spiffe://kiln.dev/gateway/" + url.PathEscape(config.InstallationID) + "/" + url.PathEscape(config.ResourceID) + "/" + url.PathEscape(config.Generation) + "/" + url.PathEscape(deviceID)
	found := false
	for _, uri := range certificate.URIs {
		if uri.String() == expected {
			found = true
		}
	}
	if !found {
		return nil, errors.New("client certificate identity mismatch")
	}
	return certificate, nil
}

func parseGatewayCertificate(certificatePEM string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid client certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid client certificate")
	}
	return certificate, nil
}

func parseGatewayTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}

func parseWholeGatewayTimestamp(value string) (time.Time, error) {
	parsed, err := parseGatewayTimestamp(value)
	if err != nil || parsed.Nanosecond() != 0 {
		return time.Time{}, errors.New("invalid timestamp")
	}
	canonical := parsed.UTC().Format(time.RFC3339)
	if value != canonical && value != parsed.UTC().Format("2006-01-02T15:04:05.000Z") {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}

func newGatewayHTTPClient(serverCAFile string, certificate *tls.Certificate) (*http.Client, error) {
	roots, err := loadCertificatePool(serverCAFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Client{Timeout: gatewayRequestTimeout, Transport: &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

func loadCertificatePool(path string) (*x509.CertPool, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxGatewayBody))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("invalid CA file")
	}
	return roots, nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe state directory")
	}
	return nil
}

func openPrivateRegularFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe private file")
	}
	return os.Open(path)
}

func openRegularFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("unsafe file")
	}
	return os.Open(path)
}

func loadOrCreateGatewayKey(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, "gateway-key.pem")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := atomicPrivateWrite(path, gatewayPrivateKeyPEM(key)); err != nil {
			return nil, err
		}
		return key, nil
	}
	file, err := openPrivateRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxGatewayBody))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid gateway key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid gateway key")
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() {
		return nil, errors.New("invalid gateway key")
	}
	return ecdsaKey, nil
}

func gatewayPrivateKeyPEM(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("P-256 key must marshal")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func loadGatewayState(dir string) (gatewayState, error) {
	path := filepath.Join(dir, "gateway-state.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return gatewayState{}, nil
	}
	file, err := openPrivateRegularFile(path)
	if err != nil {
		return gatewayState{}, err
	}
	defer file.Close()
	var state gatewayState
	decoder := json.NewDecoder(io.LimitReader(file, maxGatewayBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || !validGatewayID(state.DeviceID) || state.NextSequence < 1 {
		return state, errors.New("invalid gateway state")
	}
	return state, nil
}

func saveGatewayState(dir string, state gatewayState) error {
	contents, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicPrivateWrite(filepath.Join(dir, "gateway-state.json"), contents)
}

func atomicPrivateWrite(path string, contents []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".gateway-write-")
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(contents); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readBootstrapToken(path string) (string, error) {
	file, err := openPrivateRegularFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(contents) > 4096 {
		return "", errors.New("invalid bootstrap token file")
	}
	token := strings.TrimSpace(string(contents))
	if !validGatewayID(token) {
		return "", errors.New("invalid bootstrap token")
	}
	return token, nil
}

func acquireGatewayLock(dir string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(dir, "gateway.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another gateway daemon owns this state directory")
	}
	return file, nil
}
