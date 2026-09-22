package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDevelopmentUpSendsAuthenticatedIdempotentRequest(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Store(true)
		if request.Method != http.MethodPost || request.URL.Path != "/v1/resources" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("missing bearer token")
		}
		if !strings.HasPrefix(request.Header.Get("Idempotency-Key"), "cli-") {
			t.Fatal("missing CLI idempotency key")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["type"] != "development" || body["ttlSeconds"] != float64(7200) || body["profile"] != "node" {
			t.Fatalf("unexpected body: %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"dev_test","state":"REQUESTED"}`))
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")

	if err := run([]string{"dev", "up", "--ttl", "2h", "--profile", "node"}); err != nil {
		t.Fatal(err)
	}
	if !called.Load() {
		t.Fatal("expected Kiln API request")
	}
}

func TestClientDoesNotFollowRedirectsWithBearerToken(t *testing.T) {
	var targetCalled atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetCalled.Store(true)
		if request.Header.Get("Authorization") != "" {
			t.Fatal("redirect target received bearer token")
		}
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+"/captured", http.StatusFound)
	}))
	defer source.Close()

	t.Setenv("KILN_URL", source.URL)
	t.Setenv("KILN_TOKEN", "test-token")
	client, err := newClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.request(context.Background(), http.MethodGet, "/v1/status", nil, nil); err == nil {
		t.Fatal("expected redirect rejection")
	}
	if targetCalled.Load() {
		t.Fatal("client followed redirect")
	}
}

func TestClientDoesNotExposeAPIErrorMessages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"PVEAPIToken=secret-must-not-escape"}}`))
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")
	client, err := newClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.request(context.Background(), http.MethodGet, "/v1/status", nil, nil)
	if err == nil || strings.Contains(err.Error(), "secret-must-not-escape") || !strings.Contains(err.Error(), "HTTP 403 (UNAUTHORIZED)") {
		t.Fatalf("API error was not sanitized: %v", err)
	}
}

func TestClientRejectsAmbiguousBaseURLs(t *testing.T) {
	for _, baseURL := range []string{
		"https://token@example.test",
		"https://example.test/control",
		"https://example.test/?next=https://attacker.test",
		"https://example.test/#fragment",
	} {
		t.Run(baseURL, func(t *testing.T) {
			t.Setenv("KILN_URL", baseURL)
			t.Setenv("KILN_TOKEN", "test-token")
			if _, err := newClientFromEnv(); err == nil {
				t.Fatal("expected base URL rejection")
			}
		})
	}
}

func TestDoctorQueriesTheAPIAndReturnsAHealthExit(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Store(true)
		if request.Method != http.MethodGet || request.URL.Path != "/v1/doctor" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("missing bearer token")
		}
		if got := request.URL.Query(); got.Get("network") != "true" || got.Get("node") != "node-a" {
			t.Fatalf("unexpected doctor query: %s", got.Encode())
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"DEGRADED","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[],"incidents":[{"id":"inc_test","node":"node-a","gatewayId":"gw_test","code":"GATEWAY_STALE","severity":"critical","status":"OPEN","firstSeenAt":"2026-01-01T00:00:00Z","lastSeenAt":"2026-01-01T00:00:00Z","resolvedAt":null,"message":"Gateway heartbeat is stale.","guidance":["Inspect the gateway console."]}],"repairEnabled":false,"limitations":[]}`))
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")

	err := run([]string{"doctor", "--network", "--node", "node-a"})
	if err == nil || err.Error() != "doctor found DEGRADED readiness" {
		t.Fatalf("expected a degraded doctor result, got %v", err)
	}
	if exitCode(err) != 2 {
		t.Fatalf("expected diagnosis exit code 2, got %d", exitCode(err))
	}
	if !called.Load() {
		t.Fatal("expected a doctor API request")
	}
}

func TestDoctorTextOutputIncludesRecoveryGuidance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"DEGRADED","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[{"node":"node-a","gatewayId":null,"status":"UNCONFIGURED","checks":[{"id":"gateway","status":"WARN","code":"GATEWAY_UNCONFIGURED","message":"No Kiln gateway is configured."}]}],"incidents":[{"id":"inc_test","node":"node-a","gatewayId":null,"code":"UNCONFIGURED","severity":"warning","status":"OPEN","firstSeenAt":"2026-01-01T00:00:00Z","lastSeenAt":"2026-01-01T00:00:00Z","resolvedAt":null,"message":"Gateway is not configured.","guidance":["Create a protected gateway."]}],"repairEnabled":false,"limitations":["No repair executor is installed."]}`))
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")
	client, err := newClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := doctorCommandTo(client, []string{"--network"}, &output); err == nil || exitCode(err) != 2 {
		t.Fatalf("expected a degraded doctor result, got %v", err)
	}
	for _, want := range []string{"Overall: DEGRADED", "Node node-a: UNCONFIGURED", "Fix: Create a protected gateway.", "Repairs are unavailable"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("doctor output does not contain %q: %s", want, output.String())
		}
	}
}

func TestDoctorRejectsMalformedResponseWithoutExposingItsContents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"schemaVersion":1,"overall":"PVEAPIToken=secret-must-not-escape"}`))
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")

	err := run([]string{"doctor", "--json"})
	if err == nil || !strings.Contains(err.Error(), "invalid doctor response") || strings.Contains(err.Error(), "secret-must-not-escape") {
		t.Fatalf("expected a sanitized invalid doctor response error, got %v", err)
	}
	if exitCode(err) != 1 {
		t.Fatalf("expected transport or schema failure exit code 1, got %d", exitCode(err))
	}
}

func TestDoctorJSONOutputUsesTheVersionedReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"HEALTHY","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[{"node":"node-a","gatewayId":"gw_test","status":"READY","checks":[{"id":"gateway","status":"PASS","code":"READY","message":"Gateway is ready."}]}],"incidents":[],"repairEnabled":false,"limitations":[]}`))
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")
	client, err := newClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := doctorCommandTo(client, []string{"--json"}, &output); err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("doctor JSON was invalid: %v", err)
	}
	if report["schemaVersion"] != float64(1) || report["overall"] != "HEALTHY" {
		t.Fatalf("unexpected doctor JSON: %#v", report)
	}
}

func TestDoctorRejectsContradictoryHealthyEvidenceBeforePrinting(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "no observed nodes",
			body: `{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"HEALTHY","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[],"incidents":[],"repairEnabled":false,"limitations":[]}`,
		},
		{
			name: "warning top level check",
			body: `{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"HEALTHY","checks":[{"id":"provider","status":"WARN","code":"PROVIDER_UNKNOWN","message":"Provider cannot be observed."}],"nodes":[{"node":"node-a","gatewayId":"gw_test","status":"READY","checks":[{"id":"gateway","status":"PASS","code":"READY","message":"Gateway is ready."}]}],"incidents":[],"repairEnabled":false,"limitations":[]}`,
		},
		{
			name: "quarantined node",
			body: `{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"HEALTHY","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[{"node":"node-a","gatewayId":"gw_test","status":"QUARANTINED","checks":[{"id":"gateway","status":"FAIL","code":"OWNERSHIP_QUARANTINE","message":"Ownership does not match."}]}],"incidents":[],"repairEnabled":false,"limitations":[]}`,
		},
		{
			name: "open critical incident",
			body: `{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"HEALTHY","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[{"node":"node-a","gatewayId":"gw_test","status":"READY","checks":[{"id":"gateway","status":"PASS","code":"READY","message":"Gateway is ready."}]}],"incidents":[{"id":"inc_test","node":"node-a","gatewayId":"gw_test","code":"GATEWAY_SERVICE","severity":"critical","status":"OPEN","firstSeenAt":"2026-01-01T00:00:00Z","lastSeenAt":"2026-01-01T00:00:00Z","resolvedAt":null,"message":"PVEAPIToken=secret-must-not-escape","guidance":[]}],"repairEnabled":false,"limitations":[]}`,
		},
		{
			name: "repair enabled",
			body: `{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"HEALTHY","checks":[{"id":"provider","status":"PASS","code":"OK","message":"Provider can be observed."}],"nodes":[{"node":"node-a","gatewayId":"gw_test","status":"READY","checks":[{"id":"gateway","status":"PASS","code":"READY","message":"Gateway is ready."}]}],"incidents":[],"repairEnabled":true,"limitations":[]}`,
		},
		{
			name: "unknown nested status",
			body: `{"schemaVersion":1,"checkedAt":"2026-01-01T00:00:00Z","installationId":"installation_test","providerMode":"fake","persistence":"memory","overall":"DEGRADED","checks":[{"id":"provider","status":"MAYBE","code":"OK","message":"Provider can be observed."}],"nodes":[],"incidents":[],"repairEnabled":false,"limitations":[]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			t.Setenv("KILN_URL", server.URL)
			t.Setenv("KILN_TOKEN", "test-token")
			client, err := newClientFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = doctorCommandTo(client, []string{"--json"}, &output)
			if err == nil || !strings.Contains(err.Error(), "invalid doctor response") {
				t.Fatalf("expected invalid doctor response, got %v", err)
			}
			if exitCode(err) != 1 {
				t.Fatalf("expected invalid report exit code 1, got %d", exitCode(err))
			}
			if output.Len() != 0 || strings.Contains(output.String(), "secret-must-not-escape") {
				t.Fatalf("doctor printed an invalid report: %q", output.String())
			}
		})
	}
}

func TestDoctorRejectsRepairBeforeAnyAPIRequest(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Store(true)
		t.Fatal("doctor repair must not call the API")
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")

	err := run([]string{"doctor", "repair"})
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected unavailable repair error, got %v", err)
	}
	if called.Load() {
		t.Fatal("doctor repair made an API request")
	}
}

func TestDoctorRejectsMalformedNodeBeforeAnyAPIRequest(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Store(true)
		t.Fatal("malformed node must not call the API")
	}))
	defer server.Close()
	t.Setenv("KILN_URL", server.URL)
	t.Setenv("KILN_TOKEN", "test-token")

	err := run([]string{"doctor", "--node", "node with spaces"})
	if err == nil || !strings.Contains(err.Error(), "--node") {
		t.Fatalf("expected invalid node error, got %v", err)
	}
	if called.Load() {
		t.Fatal("malformed node made an API request")
	}
}
