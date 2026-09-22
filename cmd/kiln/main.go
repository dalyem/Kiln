package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const usage = `Kiln Phase 1 CLI

Usage:
  kiln status
	  kiln doctor [--network] [--node name] [--json]
  kiln resource list
  kiln resource get <resource-id>
  kiln resource stop <resource-id>
  kiln resource destroy <resource-id>
  kiln dev up [--ttl 2h] [--profile profile]
  kiln inventory
  kiln bootstrap proxmox [--apply]
  kiln workspace capture --repo PATH --output FILE
  kiln workspace inspect --input FILE

Normal commands require KILN_URL and KILN_TOKEN. Bootstrap only prints its
future deployment plan in Phase 1 and does not contact Proxmox.`

type client struct {
	baseURL string
	token   string
	http    *http.Client
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kiln:", err)
		os.Exit(exitCode(err))
	}
}

func exitCode(err error) int {
	var diagnosis *doctorDiagnosisError
	if errors.As(err, &diagnosis) {
		return 2
	}
	return 1
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println(usage)
		return nil
	}

	if args[0] == "bootstrap" {
		return bootstrap(args[1:])
	}
	if args[0] == "workspace" {
		return workspaceCommand(args[1:])
	}

	c, err := newClientFromEnv()
	if err != nil {
		return err
	}

	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: kiln status")
		}
		return c.print(context.Background(), http.MethodGet, "/v1/status", nil, nil)
	case "doctor":
		return doctorCommand(c, args[1:])
	case "inventory":
		if len(args) != 1 {
			return errors.New("usage: kiln inventory")
		}
		return c.print(context.Background(), http.MethodGet, "/v1/inventory", nil, nil)
	case "resource":
		return resourceCommand(c, args[1:])
	case "dev":
		return developmentCommand(c, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type doctorDiagnosisError struct {
	overall string
}

func (error *doctorDiagnosisError) Error() string {
	return "doctor found " + error.overall + " readiness"
}

type doctorCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type doctorNode struct {
	Node      string        `json:"node"`
	GatewayID *string       `json:"gatewayId"`
	Status    string        `json:"status"`
	Checks    []doctorCheck `json:"checks"`
}

type doctorIncident struct {
	ID          string   `json:"id"`
	Node        string   `json:"node"`
	GatewayID   *string  `json:"gatewayId"`
	Code        string   `json:"code"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	FirstSeenAt string   `json:"firstSeenAt"`
	LastSeenAt  string   `json:"lastSeenAt"`
	ResolvedAt  *string  `json:"resolvedAt"`
	Message     string   `json:"message"`
	Guidance    []string `json:"guidance"`
}

type doctorReport struct {
	SchemaVersion  int              `json:"schemaVersion"`
	CheckedAt      string           `json:"checkedAt"`
	InstallationID string           `json:"installationId"`
	ProviderMode   string           `json:"providerMode"`
	Persistence    string           `json:"persistence"`
	Overall        string           `json:"overall"`
	Checks         []doctorCheck    `json:"checks"`
	Nodes          []doctorNode     `json:"nodes"`
	Incidents      []doctorIncident `json:"incidents"`
	RepairEnabled  *bool            `json:"repairEnabled"`
	Limitations    []string         `json:"limitations"`
}

var nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func doctorCommand(c *client, args []string) error {
	return doctorCommandTo(c, args, os.Stdout)
}

func doctorCommandTo(c *client, args []string, output io.Writer) error {
	if len(args) > 0 && (args[0] == "repair" || args[0] == "apply") {
		return errors.New("doctor repair is unavailable in this Kiln release; no repair request was sent")
	}
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	network := flags.Bool("network", false, "include network readiness checks")
	node := flags.String("node", "", "limit checks to one Proxmox node")
	jsonOutput := flags.Bool("json", false, "print the API response as JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: kiln doctor [--network] [--node name] [--json]")
	}
	if *node != "" && !nodeNamePattern.MatchString(*node) {
		return errors.New("--node must be a Proxmox node name of up to 128 letters, digits, dots, underscores, or hyphens")
	}
	query := url.Values{}
	if *network {
		query.Set("network", "true")
	}
	if *node != "" {
		query.Set("node", *node)
	}
	path := "/v1/doctor"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	response, err := c.request(context.Background(), http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	report, err := parseDoctorReport(response)
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return err
		}
	} else {
		printDoctorReport(output, report)
	}
	if report.Overall != "HEALTHY" {
		return &doctorDiagnosisError{overall: report.Overall}
	}
	return nil
}

func parseDoctorReport(value any) (doctorReport, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return doctorReport{}, errors.New("Kiln API returned an invalid doctor response")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil || !hasDoctorFields(raw, "schemaVersion", "checkedAt", "installationId", "providerMode", "persistence", "overall", "checks", "nodes", "incidents", "repairEnabled", "limitations") {
		return doctorReport{}, errors.New("Kiln API returned an invalid doctor response")
	}
	var report doctorReport
	if err := json.Unmarshal(encoded, &report); err != nil || !validDoctorReport(report, raw) {
		return doctorReport{}, errors.New("Kiln API returned an invalid doctor response")
	}
	return report, nil
}

func validDoctorReport(report doctorReport, raw map[string]json.RawMessage) bool {
	if report.SchemaVersion != 1 || !knownDoctorOverall(report.Overall) || report.CheckedAt == "" || !validDoctorTimestamp(report.CheckedAt) || report.InstallationID == "" || report.ProviderMode == "" || report.Persistence == "" || report.RepairEnabled == nil || *report.RepairEnabled || report.Checks == nil || report.Nodes == nil || report.Incidents == nil || report.Limitations == nil || len(report.Checks) == 0 {
		return false
	}
	rawChecks, ok := doctorObjectArray(raw["checks"])
	if !ok || len(rawChecks) != len(report.Checks) {
		return false
	}
	for index, check := range report.Checks {
		if !hasDoctorFields(rawChecks[index], "id", "status", "code", "message") || !validDoctorCheck(check) {
			return false
		}
	}
	rawNodes, ok := doctorObjectArray(raw["nodes"])
	if !ok || len(rawNodes) != len(report.Nodes) {
		return false
	}
	for index, node := range report.Nodes {
		if !hasDoctorFields(rawNodes[index], "node", "gatewayId", "status", "checks") || !validDoctorNode(node) {
			return false
		}
		rawNodeChecks, ok := doctorObjectArray(rawNodes[index]["checks"])
		if !ok || len(rawNodeChecks) != len(node.Checks) || len(node.Checks) == 0 {
			return false
		}
		for checkIndex, check := range node.Checks {
			if !hasDoctorFields(rawNodeChecks[checkIndex], "id", "status", "code", "message") || !validDoctorCheck(check) {
				return false
			}
		}
	}
	rawIncidents, ok := doctorObjectArray(raw["incidents"])
	if !ok || len(rawIncidents) != len(report.Incidents) {
		return false
	}
	for index, incident := range report.Incidents {
		if !hasDoctorFields(rawIncidents[index], "id", "node", "gatewayId", "code", "severity", "status", "firstSeenAt", "lastSeenAt", "resolvedAt", "message", "guidance") || !validDoctorIncident(incident) {
			return false
		}
	}
	if report.Overall == "HEALTHY" {
		if len(report.Nodes) == 0 {
			return false
		}
		for _, check := range report.Checks {
			if check.Status != "PASS" {
				return false
			}
		}
		for _, node := range report.Nodes {
			if node.Status != "READY" {
				return false
			}
			for _, check := range node.Checks {
				if check.Status != "PASS" {
					return false
				}
			}
		}
		for _, incident := range report.Incidents {
			if incident.Status == "OPEN" && incident.Severity == "critical" {
				return false
			}
		}
	}
	return true
}

func hasDoctorFields(object map[string]json.RawMessage, fields ...string) bool {
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return false
		}
	}
	return true
}

func doctorObjectArray(value json.RawMessage) ([]map[string]json.RawMessage, bool) {
	var objects []map[string]json.RawMessage
	if len(value) == 0 || json.Unmarshal(value, &objects) != nil || objects == nil {
		return nil, false
	}
	return objects, true
}

func validDoctorCheck(check doctorCheck) bool {
	return check.ID != "" && check.Code != "" && check.Message != "" && knownDoctorCheckStatus(check.Status)
}

func validDoctorNode(node doctorNode) bool {
	if node.Node == "" || node.Checks == nil || !knownDoctorNodeStatus(node.Status) {
		return false
	}
	if node.Status == "UNCONFIGURED" {
		return node.GatewayID == nil
	}
	return node.GatewayID != nil && *node.GatewayID != ""
}

func validDoctorIncident(incident doctorIncident) bool {
	if incident.ID == "" || incident.Node == "" || incident.Code == "" || incident.Message == "" || incident.Guidance == nil || !knownDoctorSeverity(incident.Severity) || !knownDoctorIncidentStatus(incident.Status) || !validDoctorTimestamp(incident.FirstSeenAt) || !validDoctorTimestamp(incident.LastSeenAt) || (incident.GatewayID != nil && *incident.GatewayID == "") {
		return false
	}
	if incident.ResolvedAt != nil && !validDoctorTimestamp(*incident.ResolvedAt) {
		return false
	}
	for _, guidance := range incident.Guidance {
		if guidance == "" {
			return false
		}
	}
	return true
}

func validDoctorTimestamp(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func knownDoctorOverall(value string) bool {
	return value == "HEALTHY" || value == "DEGRADED" || value == "UNKNOWN"
}

func knownDoctorCheckStatus(value string) bool {
	return value == "PASS" || value == "WARN" || value == "FAIL" || value == "UNKNOWN"
}

func knownDoctorNodeStatus(value string) bool {
	return value == "READY" || value == "NOT_READY" || value == "QUARANTINED" || value == "UNCONFIGURED"
}

func knownDoctorSeverity(value string) bool {
	return value == "warning" || value == "critical"
}

func knownDoctorIncidentStatus(value string) bool {
	return value == "OPEN" || value == "RESOLVED"
}

func printDoctorReport(output io.Writer, report doctorReport) {
	fmt.Fprintf(output, "Overall: %s\n", report.Overall)
	if report.CheckedAt != "" {
		fmt.Fprintf(output, "Observed: %s\n", report.CheckedAt)
	}
	for _, check := range report.Checks {
		fmt.Fprintf(output, "%s  %s  %s\n", check.Status, check.ID, check.Message)
	}
	for _, node := range report.Nodes {
		gatewayID := "unconfigured"
		if node.GatewayID != nil {
			gatewayID = *node.GatewayID
		}
		fmt.Fprintf(output, "Node %s: %s (%s)\n", node.Node, node.Status, gatewayID)
		for _, check := range node.Checks {
			fmt.Fprintf(output, "  %s  %s  %s\n", check.Status, check.ID, check.Message)
		}
	}
	for _, incident := range report.Incidents {
		fmt.Fprintf(output, "Incident %s: %s on %s. %s\n", incident.ID, incident.Code, incident.Node, incident.Message)
		for _, guidance := range incident.Guidance {
			fmt.Fprintf(output, "  Fix: %s\n", guidance)
		}
	}
	if report.RepairEnabled == nil || !*report.RepairEnabled {
		fmt.Fprintln(output, "Repairs are unavailable in this Kiln release. Doctor only reports evidence and recovery guidance.")
	}
	for _, limitation := range report.Limitations {
		fmt.Fprintf(output, "Limitation: %s\n", limitation)
	}
}

func newClientFromEnv() (*client, error) {
	baseURL := strings.TrimRight(os.Getenv("KILN_URL"), "/")
	token := os.Getenv("KILN_TOKEN")
	if baseURL == "" || token == "" {
		return nil, errors.New("KILN_URL and KILN_TOKEN must be set")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("KILN_URL must be an HTTP(S) origin without credentials, path, query, or fragment")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("KILN_URL must use http or https")
	}
	return &client{baseURL: baseURL, token: token, http: &http.Client{
		Timeout: 15 * time.Second,
		// A redirect can cross a trust boundary. Do not forward the bearer token.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func resourceCommand(c *client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kiln resource <list|get|stop|destroy>")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: kiln resource list")
		}
		return c.print(context.Background(), http.MethodGet, "/v1/resources", nil, nil)
	case "get", "stop", "destroy":
		if len(args) != 2 || args[1] == "" {
			return fmt.Errorf("usage: kiln resource %s <resource-id>", args[0])
		}
		resourceID := url.PathEscape(args[1])
		method, path := http.MethodGet, "/v1/resources/"+resourceID
		if args[0] == "stop" {
			method, path = http.MethodPost, path+"/stop"
		}
		if args[0] == "destroy" {
			method = http.MethodDelete
		}
		return c.print(context.Background(), method, path, map[string]any{}, nil)
	default:
		return fmt.Errorf("unknown resource command %q", args[0])
	}
}

func developmentCommand(c *client, args []string) error {
	if len(args) == 0 || args[0] != "up" {
		return errors.New("usage: kiln dev up [--ttl 2h] [--profile profile]")
	}
	flags := flag.NewFlagSet("dev up", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ttl := flags.String("ttl", "1h", "lease duration between 60 seconds and 24 hours")
	profile := flags.String("profile", "", "development profile")
	if err := flags.Parse(args[1:]); err != nil {
		return errors.New("usage: kiln dev up [--ttl 2h] [--profile profile]")
	}
	if flags.NArg() != 0 {
		return errors.New("usage: kiln dev up [--ttl 2h] [--profile profile]")
	}
	duration, err := time.ParseDuration(*ttl)
	if err != nil || duration < time.Minute || duration > 24*time.Hour || duration%time.Second != 0 {
		return errors.New("--ttl must be a whole-second duration between 1m and 24h")
	}
	body := map[string]any{"type": "development", "projectId": "default", "ttlSeconds": int(duration.Seconds())}
	if *profile != "" {
		body["profile"] = *profile
	}
	key, err := newIdempotencyKey()
	if err != nil {
		return err
	}
	return c.print(context.Background(), http.MethodPost, "/v1/resources", body, map[string]string{"Idempotency-Key": key})
}

func bootstrap(args []string) error {
	if len(args) == 0 || args[0] != "proxmox" {
		return errors.New("usage: kiln bootstrap proxmox [--apply]")
	}
	flags := flag.NewFlagSet("bootstrap proxmox", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	apply := flags.Bool("apply", false, "apply the Proxmox bootstrap plan")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("usage: kiln bootstrap proxmox [--apply]")
	}
	if *apply {
		return errors.New("Proxmox bootstrap apply is unsupported in Phase 1; no Proxmox changes were made")
	}
	fmt.Println("Phase 1 Proxmox bootstrap plan only. A later version will validate credentials, discover storage and bridges, create the kiln pool, import the appliance, and create the control-plane VM. This command made no network calls and no Proxmox changes.")
	return nil
}

func (c *client) print(ctx context.Context, method, path string, body any, headers map[string]string) error {
	response, err := c.request(ctx, method, path, body, headers)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(response)
}

func (c *client) request(ctx context.Context, method, path string, body any, headers map[string]string) (any, error) {
	var reader io.Reader
	if body != nil && method != http.MethodGet && method != http.MethodDelete {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if reader != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Kiln API request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 1<<20)
	decoded := map[string]any{}
	if err := json.NewDecoder(limited).Decode(&decoded); err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New("Kiln API returned an invalid JSON response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Kiln API request failed with HTTP %d (%s)", response.StatusCode, safeErrorCode(decoded))
	}
	return decoded, nil
}

func safeErrorCode(decoded map[string]any) string {
	errorValue, ok := decoded["error"].(map[string]any)
	if !ok {
		return "request_failed"
	}
	code, ok := errorValue["code"].(string)
	if ok && knownErrorCodes[code] {
		return code
	}
	return "request_failed"
}

var knownErrorCodes = map[string]bool{
	"CONFLICT":             true,
	"IDEMPOTENCY_CONFLICT": true,
	"INTERNAL":             true,
	"INVALID_INPUT":        true,
	"NOT_FOUND":            true,
	"PROVIDER_FAILURE":     true,
	"SAFETY_DENIED":        true,
	"UNAUTHENTICATED":      true,
	"UNAUTHORIZED":         true,
	"UNSUPPORTED":          true,
}

func newIdempotencyKey() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("create idempotency key: %w", err)
	}
	return "cli-" + hex.EncodeToString(bytes), nil
}
