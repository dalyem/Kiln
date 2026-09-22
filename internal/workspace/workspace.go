// Package workspace captures and reconstructs bounded Git workspaces.
package workspace

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	version         = 1
	maxSnapshotSize = 96 << 20
	maxRawBytes     = 64 << 20
	maxBlobSize     = 16 << 20
	maxEntries      = 10_000
	maxPathSize     = 4 << 10
)

// Summary contains only metadata that is safe to print from a snapshot.
type Summary struct {
	Digest   string `json:"digest"`
	HEAD     string `json:"head"`
	HeadTree int    `json:"headTreeEntries"`
	Index    int    `json:"indexEntries"`
	Worktree int    `json:"worktreeEntries"`
	Blobs    int    `json:"blobs"`
	Policy   string `json:"policy"`
}

type snapshot struct {
	Version  int     `json:"version"`
	Head     head    `json:"head"`
	HeadTree []entry `json:"headTree"`
	Index    []entry `json:"index"`
	Worktree []entry `json:"worktree"`
	Blobs    []blob  `json:"blobs"`
}

type head struct {
	OID    string `json:"oid"`
	Tree   string `json:"tree"`
	Commit []byte `json:"commit"`
}

type entry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Digest string `json:"digest"`
	Kind   string `json:"kind"`
}

type blob struct {
	Digest string `json:"digest"`
	Data   []byte `json:"data"`
}

// Capture observes a repository twice and returns a deterministic snapshot.
func Capture(repo string) ([]byte, Summary, error) {
	if err := rejectGitEnvironmentOverrides(); err != nil {
		return nil, Summary{}, err
	}
	first, err := observe(repo)
	if err != nil {
		return nil, Summary{}, err
	}
	second, err := observe(repo)
	if err != nil {
		return nil, Summary{}, err
	}
	firstBytes, err := marshalSnapshot(first)
	if err != nil {
		return nil, Summary{}, err
	}
	secondBytes, err := marshalSnapshot(second)
	if err != nil {
		return nil, Summary{}, err
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		return nil, Summary{}, errors.New("repository changed during capture; pause writers and retry")
	}
	return firstBytes, summary(firstBytes, first), nil
}

// CaptureFile captures repo without replacing an existing output file.
func CaptureFile(repo, output string) (Summary, error) {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return Summary{}, err
	}
	outputAbs, err := filepath.Abs(output)
	if err != nil {
		return Summary{}, err
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(outputAbs))
	if err != nil {
		return Summary{}, fmt.Errorf("resolve snapshot output parent: %w", err)
	}
	outputAbs = filepath.Join(outputParent, filepath.Base(outputAbs))
	if err := trustedOutputDirectory(outputParent); err != nil {
		return Summary{}, err
	}
	repoRoot, err := repositoryRoot(repoAbs)
	if err != nil {
		return Summary{}, err
	}
	if isWithin(repoRoot, outputAbs) {
		return Summary{}, errors.New("--output must be outside the source repository")
	}
	data, result, err := Capture(repoRoot)
	if err != nil {
		return Summary{}, err
	}
	parent := filepath.Dir(outputAbs)
	file, err := os.CreateTemp(parent, ".kiln-workspace-")
	if err != nil {
		return Summary{}, fmt.Errorf("create private snapshot staging file: %w", err)
	}
	staging := file.Name()
	defer os.Remove(staging)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return Summary{}, fmt.Errorf("set snapshot permissions: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return Summary{}, fmt.Errorf("write snapshot output: %w", err)
	}
	if err := file.Close(); err != nil {
		return Summary{}, fmt.Errorf("close snapshot output: %w", err)
	}
	if err := os.Link(staging, outputAbs); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Summary{}, errors.New("snapshot output already exists")
		}
		return Summary{}, fmt.Errorf("publish snapshot output: %w", err)
	}
	return result, nil
}

// Inspect validates snapshot bytes before returning non-content metadata.
func Inspect(data []byte) (Summary, error) {
	s, err := parseSnapshot(data)
	if err != nil {
		return Summary{}, err
	}
	return summary(data, s), nil
}

// InspectFile reads a bounded snapshot file and validates it.
func InspectFile(input string) (Summary, error) {
	data, err := readSnapshotFile(input)
	if err != nil {
		return Summary{}, err
	}
	return Inspect(data)
}

// Materialize validates and reconstructs snapshot at an absent destination.
func Materialize(data []byte, destination string) (Summary, error) {
	s, err := parseSnapshot(data)
	if err != nil {
		return Summary{}, err
	}
	if err := materialize(s, destination); err != nil {
		return Summary{}, err
	}
	return summary(data, s), nil
}

// MaterializeFile reads a bounded snapshot before materializing it.
func MaterializeFile(input, destination string) (Summary, error) {
	data, err := readSnapshotFile(input)
	if err != nil {
		return Summary{}, err
	}
	return Materialize(data, destination)
}

func observe(repo string) (snapshot, error) {
	if !filepath.IsAbs(repo) {
		var err error
		repo, err = filepath.Abs(repo)
		if err != nil {
			return snapshot{}, err
		}
	}
	root, err := repositoryRoot(repo)
	if err != nil {
		return snapshot{}, err
	}
	repo = root
	format, err := git(repo, "rev-parse", "--show-object-format")
	if err != nil || strings.TrimSpace(string(format)) != "sha1" {
		return snapshot{}, errors.New("only SHA1 Git repositories are supported")
	}
	if isPartialClone(repo) {
		return snapshot{}, errors.New("partial clone repositories are unsupported")
	}
	if _, err := os.Lstat(filepath.Join(repo, ".git", "index.lock")); err == nil {
		return snapshot{}, errors.New("repository index is locked")
	} else if !errors.Is(err, os.ErrNotExist) {
		return snapshot{}, fmt.Errorf("check repository index lock: %w", err)
	}
	headOIDBytes, err := git(repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return snapshot{}, errors.New("repository must have a committed HEAD")
	}
	headOID := strings.TrimSpace(string(headOIDBytes))
	if !validOID(headOID) {
		return snapshot{}, errors.New("repository HEAD is not a SHA1 commit")
	}
	commit, err := gitLimit(repo, maxBlobSize, "cat-file", "commit", headOID)
	if err != nil {
		return snapshot{}, errors.New("read HEAD commit")
	}
	tree, _, err := parseCommit(commit)
	if err != nil {
		return snapshot{}, err
	}
	actualOID := gitObjectID("commit", commit)
	if actualOID != headOID {
		return snapshot{}, errors.New("HEAD commit did not match its object ID")
	}
	headEntries, err := gitEntries(repo, "ls-tree", "-rz", "HEAD")
	if err != nil {
		return snapshot{}, err
	}
	indexEntries, err := gitEntries(repo, "ls-files", "-s", "-z")
	if err != nil {
		return snapshot{}, err
	}
	if err := rejectIndexFeatures(repo, indexEntries); err != nil {
		return snapshot{}, err
	}
	paths, err := git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return snapshot{}, fmt.Errorf("list working files: %w", err)
	}
	remainingEntries := maxEntries - len(headEntries) - len(indexEntries)
	if remainingEntries < 0 {
		return snapshot{}, fmt.Errorf("snapshot has more than %d entries", maxEntries)
	}
	worktreeEntries, contents, err := worktreeEntries(repo, paths, remainingEntries)
	if err != nil {
		return snapshot{}, err
	}
	gitBlobs := make(map[string]string)
	for _, items := range [][]entry{headEntries, indexEntries} {
		for index := range items {
			oid := items[index].Digest
			digest, known := gitBlobs[oid]
			if !known {
				data, err := gitBlob(repo, oid)
				if err != nil {
					return snapshot{}, fmt.Errorf("read Git blob for %q: %w", items[index].Path, err)
				}
				digest = contentDigest(data)
				if err := addContent(contents, digest, data); err != nil {
					return snapshot{}, err
				}
				gitBlobs[oid] = digest
			}
			items[index].Digest = digest
		}
	}
	all := append(append(append([]entry{}, headEntries...), indexEntries...), worktreeEntries...)
	if err := rejectLFS(repo, all, contents); err != nil {
		return snapshot{}, err
	}
	blobs, err := makeBlobs(contents)
	if err != nil {
		return snapshot{}, err
	}
	s := snapshot{Version: version, Head: head{OID: headOID, Tree: tree, Commit: commit}, HeadTree: headEntries, Index: indexEntries, Worktree: worktreeEntries, Blobs: blobs}
	if err := validateSnapshot(s); err != nil {
		return snapshot{}, err
	}
	return s, nil
}

func marshalSnapshot(s snapshot) ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > maxSnapshotSize {
		return nil, fmt.Errorf("encoded snapshot exceeds %d bytes", maxSnapshotSize)
	}
	return append(data, '\n'), nil
}

func summary(data []byte, s snapshot) Summary {
	digest := sha256.Sum256(data)
	return Summary{Digest: hex.EncodeToString(digest[:]), HEAD: s.Head.OID, HeadTree: len(s.HeadTree), Index: len(s.Index), Worktree: len(s.Worktree), Blobs: len(s.Blobs), Policy: "v1-sha1-raw-no-filters"}
}

func git(repo string, args ...string) ([]byte, error) {
	return gitLimit(repo, maxSnapshotSize, args...)
}

func gitLimit(repo string, limit int, args ...string) ([]byte, error) {
	context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arguments := []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.useReplaceRefs=false", "-c", "core.fileMode=true", "-c", "protocol.allow=never", "-c", "protocol.file.allow=never", "-c", "protocol.ssh.allow=never", "-c", "protocol.git.allow=never", "-c", "protocol.http.allow=never", "-c", "protocol.https.allow=never", "-c", "protocol.ext.allow=never", "--no-optional-locks"}
	arguments = append(arguments, args...)
	command := exec.CommandContext(context, "git", arguments...)
	command.Dir = repo
	command.Env = cleanEnv()
	var output limitedBuffer
	output.limit = limit
	command.Stdout = &output
	err := command.Run()
	if context.Err() != nil {
		return nil, errors.New("Git command timed out")
	}
	if err != nil {
		return nil, err
	}
	if output.exceeded {
		return nil, errors.New("Git command output exceeds snapshot limit")
	}
	return output.Bytes(), nil
}

func gitBlob(repo, oid string) ([]byte, error) {
	if !validOID(oid) {
		return nil, errors.New("invalid Git blob ID")
	}
	sizeOutput, err := gitLimit(repo, 64, "cat-file", "-s", oid)
	if err != nil {
		return nil, err
	}
	size, err := strconv.Atoi(strings.TrimSpace(string(sizeOutput)))
	if err != nil || size < 0 || size > maxBlobSize {
		return nil, fmt.Errorf("blob exceeds %d bytes", maxBlobSize)
	}
	data, err := gitLimit(repo, maxBlobSize, "cat-file", "blob", oid)
	if err != nil || len(data) != size || gitObjectID("blob", data) != oid {
		return nil, errors.New("Git blob changed while reading")
	}
	return data, nil
}

func cleanEnv() []string {
	output := make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(name, "GIT_") || name == "SSH_ASKPASS" || name == "GIT_ASKPASS" {
			continue
		}
		output = append(output, item)
	}
	return output
}

func rejectGitEnvironmentOverrides() error {
	blocked := map[string]bool{
		"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_COMMON_DIR": true, "GIT_INDEX_FILE": true,
		"GIT_OBJECT_DIRECTORY": true, "GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_REPLACE_REF_BASE": true,
		"GIT_CEILING_DIRECTORIES": true, "GIT_DISCOVERY_ACROSS_FILESYSTEM": true, "GIT_OPTIONAL_LOCKS": true,
	}
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if blocked[name] || strings.HasPrefix(name, "GIT_CONFIG_") {
			return fmt.Errorf("Git environment override %s is unsupported for workspace capture", name)
		}
	}
	return nil
}

func gitObjectID(kind string, data []byte) string {
	hash := sha1.New()
	_, _ = hash.Write([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))))
	_, _ = hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func parseCommit(data []byte) (string, []string, error) {
	separator := bytes.Index(data, []byte("\n\n"))
	if separator < 0 {
		return "", nil, errors.New("HEAD commit has no header separator")
	}
	var tree string
	var parents []string
	for _, line := range bytes.Split(data[:separator], []byte("\n")) {
		key, value, found := bytes.Cut(line, []byte(" "))
		if !found {
			continue
		}
		switch string(key) {
		case "tree":
			tree = string(value)
		case "parent":
			parents = append(parents, string(value))
		}
	}
	if !validOID(tree) {
		return "", nil, errors.New("HEAD commit has an invalid tree")
	}
	for _, parent := range parents {
		if !validOID(parent) {
			return "", nil, errors.New("HEAD commit has an invalid parent")
		}
	}
	return tree, parents, nil
}

func validOID(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func isWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func decodeData(value string) ([]byte, error) { return base64.StdEncoding.DecodeString(value) }

func gitEntries(repo string, args ...string) ([]entry, error) {
	data, err := git(repo, args...)
	if err != nil {
		return nil, fmt.Errorf("read Git entries: %w", err)
	}
	parts := bytes.Split(data, []byte{0})
	entries := make([]entry, 0, len(parts))
	for _, part := range parts[:len(parts)-1] {
		metadata, path, found := bytes.Cut(part, []byte{'\t'})
		if !found {
			return nil, errors.New("Git returned an invalid tree entry")
		}
		fields := bytes.Fields(metadata)
		if len(fields) < 3 {
			return nil, errors.New("Git returned an invalid tree entry")
		}
		mode, kind, oid := string(fields[0]), string(fields[1]), string(fields[2])
		if args[0] == "ls-files" {
			mode, oid = string(fields[0]), string(fields[1])
			kind = "blob"
			if string(fields[2]) != "0" {
				return nil, fmt.Errorf("conflicted index entry at %q", string(path))
			}
		}
		if kind == "commit" || mode == "160000" {
			return nil, fmt.Errorf("gitlinks and submodules are unsupported at %q", string(path))
		}
		if kind != "blob" || !validOID(oid) {
			return nil, fmt.Errorf("unsupported Git entry at %q", string(path))
		}
		entryKind := "file"
		if mode == "120000" {
			entryKind = "symlink"
		} else if mode != "100644" && mode != "100755" {
			return nil, fmt.Errorf("unsupported file mode %q at %q", mode, string(path))
		}
		entries = append(entries, entry{Path: string(path), Mode: mode, Digest: oid, Kind: entryKind})
	}
	if len(entries) > maxEntries {
		return nil, fmt.Errorf("snapshot has more than %d entries", maxEntries)
	}
	return entries, nil
}

func rejectIndexFeatures(repo string, entries []entry) error {
	if _, err := git(repo, "rev-parse", "--is-shallow-repository"); err != nil {
		return errors.New("read repository state")
	}
	config, err := git(repo, "config", "--get", "extensions.objectformat")
	if err == nil && strings.TrimSpace(string(config)) == "sha256" {
		return errors.New("only SHA1 Git repositories are supported")
	}
	if sparse, err := git(repo, "config", "--bool", "core.sparseCheckout"); err == nil && strings.TrimSpace(string(sparse)) == "true" {
		return errors.New("sparse checkouts are unsupported")
	}
	flags, err := git(repo, "ls-files", "-v", "-z")
	if err != nil {
		return errors.New("read Git index flags")
	}
	for _, value := range bytes.Split(flags, []byte{0}) {
		if len(value) < 3 {
			continue
		}
		prefix := value[0]
		if (prefix >= 'a' && prefix <= 'z') || prefix == 'S' {
			return errors.New("assume-unchanged or skip-worktree index entries are unsupported")
		}
	}
	debug, err := git(repo, "ls-files", "--debug", "-z")
	if err != nil {
		return errors.New("read Git index flags")
	}
	if err := rejectDebugIndexFlags(debug); err != nil {
		return err
	}
	stages, err := git(repo, "ls-files", "--stage", "-z")
	if err != nil {
		return errors.New("read Git index stages")
	}
	for _, value := range bytes.Split(stages, []byte{0}) {
		if len(value) == 0 {
			continue
		}
		metadata, _, found := bytes.Cut(value, []byte{'\t'})
		if !found {
			return errors.New("read Git index stages")
		}
		fields := bytes.Fields(metadata)
		if len(fields) != 3 || !bytes.HasSuffix(fields[2], []byte("0")) {
			return errors.New("conflicted index entries are unsupported")
		}
	}
	for _, item := range entries {
		if item.Mode == "160000" {
			return fmt.Errorf("gitlinks and submodules are unsupported at %q", item.Path)
		}
	}
	return nil
}

func rejectDebugIndexFlags(data []byte) error {
	for position := 0; position < len(data); {
		pathEnd := bytes.IndexByte(data[position:], 0)
		if pathEnd < 0 {
			return errors.New("read Git index flags")
		}
		position += pathEnd + 1
		lines := make([][]byte, 5)
		for index := range lines {
			lineEnd := bytes.IndexByte(data[position:], '\n')
			if lineEnd < 0 {
				return errors.New("read Git index flags")
			}
			lines[index] = data[position : position+lineEnd]
			position += lineEnd + 1
		}
		if !bytes.HasPrefix(lines[0], []byte("  ctime: ")) || !bytes.HasPrefix(lines[1], []byte("  mtime: ")) || !bytes.HasPrefix(lines[2], []byte("  dev: ")) || !bytes.HasPrefix(lines[3], []byte("  uid: ")) {
			return errors.New("read Git index flags")
		}
		flagPosition := bytes.LastIndex(lines[4], []byte("\tflags: "))
		if !bytes.HasPrefix(lines[4], []byte("  size: ")) || flagPosition < 0 {
			return errors.New("read Git index flags")
		}
		flags, err := strconv.ParseUint(string(lines[4][flagPosition+len("\tflags: "):]), 16, 32)
		if err != nil || flags&0x4000 != 0 || flags&0x20000000 != 0 {
			return errors.New("assume-unchanged, skip-worktree, or intent-to-add index entries are unsupported")
		}
	}
	return nil
}

func isPartialClone(repo string) bool {
	for _, pattern := range []string{`^remote\..*\.promisor$`, `^extensions\.partialClone$`} {
		value, err := git(repo, "config", "--get-regexp", pattern)
		if err == nil && len(bytes.TrimSpace(value)) != 0 {
			return true
		}
	}
	return false
}

func worktreeEntries(repo string, paths []byte, limit int) ([]entry, map[string][]byte, error) {
	contents := make(map[string][]byte)
	entries := make([]entry, 0)
	for _, rawPath := range bytes.Split(paths, []byte{0}) {
		if len(rawPath) == 0 {
			continue
		}
		if len(entries) >= limit {
			return nil, nil, fmt.Errorf("snapshot has more than %d entries", maxEntries)
		}
		path := string(rawPath)
		if err := validPath(path); err != nil {
			return nil, nil, err
		}
		fullPath := filepath.Join(repo, filepath.FromSlash(path))
		info, err := os.Lstat(fullPath)
		if errors.Is(err, os.ErrNotExist) {
			continue // A staged deletion may still have no working file.
		}
		if err != nil {
			return nil, nil, fmt.Errorf("lstat %q: %w", path, err)
		}
		if info.Mode().IsRegular() {
			data, err := readRegular(repo, path, info)
			if err != nil {
				return nil, nil, fmt.Errorf("read %q: %w", path, err)
			}
			digest := contentDigest(data)
			if err := addContent(contents, digest, data); err != nil {
				return nil, nil, err
			}
			mode := "100644"
			if info.Mode().Perm()&0o100 != 0 {
				mode = "100755"
			}
			entries = append(entries, entry{Path: path, Mode: mode, Digest: digest, Kind: "file"})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := readSymlink(repo, path, info)
			if err != nil || !safeLinkTarget(target) {
				return nil, nil, fmt.Errorf("unsafe symlink at %q", path)
			}
			data := []byte(target)
			digest := contentDigest(data)
			if err := addContent(contents, digest, data); err != nil {
				return nil, nil, err
			}
			entries = append(entries, entry{Path: path, Mode: "120000", Digest: digest, Kind: "symlink"})
			continue
		}
		return nil, nil, fmt.Errorf("unsupported special file at %q", path)
	}
	return entries, contents, nil
}

func addContent(contents map[string][]byte, digest string, data []byte) error {
	if existing, found := contents[digest]; found {
		if !bytes.Equal(existing, data) {
			return errors.New("content digest collision")
		}
		return nil
	}
	total := len(data)
	for _, existing := range contents {
		total += len(existing)
	}
	if total > maxRawBytes {
		return fmt.Errorf("snapshot raw content exceeds %d bytes", maxRawBytes)
	}
	contents[digest] = data
	return nil
}

func contentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func makeBlobs(contents map[string][]byte) ([]blob, error) {
	keys := make([]string, 0, len(contents))
	total := 0
	for digest, data := range contents {
		if !validDigest(digest) || contentDigest(data) != digest || len(data) > maxBlobSize {
			return nil, errors.New("invalid blob content")
		}
		total += len(data)
		if total > maxRawBytes {
			return nil, fmt.Errorf("snapshot raw content exceeds %d bytes", maxRawBytes)
		}
		keys = append(keys, digest)
	}
	sort.Strings(keys)
	blobs := make([]blob, 0, len(keys))
	for _, digest := range keys {
		blobs = append(blobs, blob{Digest: digest, Data: contents[digest]})
	}
	return blobs, nil
}

func rejectLFS(repo string, entries []entry, contents map[string][]byte) error {
	paths := make([]string, 0, len(entries))
	for _, item := range entries {
		paths = append(paths, item.Path)
		if bytes.HasPrefix(contents[item.Digest], []byte("version https://git-lfs.github.com/spec/v1\n")) {
			return fmt.Errorf("Git LFS pointer at %q is unsupported", item.Path)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	arguments := append([]string{"check-attr", "-z", "filter", "--"}, paths...)
	output, err := git(repo, arguments...)
	if err != nil {
		return errors.New("read Git attributes")
	}
	fields := bytes.Split(output, []byte{0})
	if len(fields)%3 != 1 {
		return errors.New("Git returned malformed attributes")
	}
	for index := 0; index+2 < len(fields)-1; index += 3 {
		if !bytes.Equal(fields[index+1], []byte("filter")) {
			return errors.New("Git returned malformed attributes")
		}
		value := string(fields[index+2])
		if value == "lfs" {
			return errors.New("Git LFS attributed paths are unsupported")
		}
		if value != "unspecified" && value != "unset" {
			return errors.New("Git filter attributed paths are unsupported")
		}
	}
	return nil
}

func validPath(path string) error {
	if path == "" || len(path) > maxPathSize || !utf8.ValidString(path) || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("invalid snapshot path %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || part == ".git" {
			return fmt.Errorf("invalid snapshot path %q", path)
		}
	}
	return nil
}

func safeLinkTarget(target string) bool {
	if target == "" || len(target) > maxPathSize || !utf8.ValidString(target) || strings.HasPrefix(target, "/") || strings.Contains(target, "\\") || strings.IndexByte(target, 0) >= 0 {
		return false
	}
	for _, part := range strings.Split(target, "/") {
		if part == "" || part == "." || part == ".." || part == ".git" {
			return false
		}
	}
	return true
}

func repositoryRoot(repo string) (string, error) {
	requested, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return "", errors.New("--repo must name a real directory")
	}
	root, err := git(repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.New("--repo must name a Git working tree")
	}
	rootPath, err := filepath.EvalSymlinks(strings.TrimSpace(string(root)))
	if err != nil {
		return "", errors.New("Git returned an invalid repository root")
	}
	if !filepath.IsAbs(rootPath) {
		return "", errors.New("Git returned an invalid repository root")
	}
	if !isWithin(rootPath, requested) {
		return "", errors.New("Git working tree is outside --repo")
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("repository root must be a real directory")
	}
	gitPath, err := os.Lstat(filepath.Join(rootPath, ".git"))
	if err != nil || !gitPath.IsDir() || gitPath.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("linked worktrees are unsupported")
	}
	return rootPath, nil
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readSnapshotFile(input string) ([]byte, error) {
	file, err := openSnapshotFile(input)
	if err != nil {
		return nil, fmt.Errorf("open snapshot input: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat snapshot input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxSnapshotSize {
		return nil, errors.New("snapshot input must be a regular file within the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotSize+1))
	if err != nil {
		return nil, fmt.Errorf("read snapshot input: %w", err)
	}
	if len(data) > maxSnapshotSize {
		return nil, errors.New("snapshot input exceeds the size limit")
	}
	return data, nil
}

func parseSnapshot(data []byte) (snapshot, error) {
	if len(data) == 0 || len(data) > maxSnapshotSize {
		return snapshot{}, errors.New("snapshot exceeds the size limit")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return snapshot{}, fmt.Errorf("invalid snapshot JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value snapshot
	if err := decoder.Decode(&value); err != nil {
		return snapshot{}, errors.New("invalid snapshot JSON")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return snapshot{}, errors.New("snapshot has trailing data")
	}
	if err := validateSnapshot(value); err != nil {
		return snapshot{}, err
	}
	return value, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return scanJSONValue(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if canonical, known := canonicalJSONKeys[strings.ToLower(name)]; known && name != canonical {
				return fmt.Errorf("noncanonical key %q", name)
			}
			if _, exists := keys[name]; exists {
				return fmt.Errorf("duplicate key %q", name)
			}
			keys[name] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

var canonicalJSONKeys = map[string]string{
	"version": "version", "head": "head", "headtree": "headTree", "index": "index", "worktree": "worktree", "blobs": "blobs",
	"oid": "oid", "tree": "tree", "commit": "commit", "path": "path", "mode": "mode", "digest": "digest", "kind": "kind", "data": "data",
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("extra JSON value")
		}
		return err
	}
	return nil
}

func validateSnapshot(s snapshot) error {
	if s.Version != version || !validOID(s.Head.OID) || !validOID(s.Head.Tree) || len(s.Head.Commit) == 0 || len(s.Head.Commit) > maxBlobSize {
		return errors.New("snapshot has an unsupported version or invalid HEAD")
	}
	tree, _, err := parseCommit(s.Head.Commit)
	if err != nil || tree != s.Head.Tree || gitObjectID("commit", s.Head.Commit) != s.Head.OID {
		return errors.New("snapshot HEAD does not match its raw commit")
	}
	if len(s.HeadTree)+len(s.Index)+len(s.Worktree) > maxEntries {
		return fmt.Errorf("snapshot has more than %d entries", maxEntries)
	}
	contents := make(map[string][]byte, len(s.Blobs))
	total := len(s.Head.Commit)
	for _, item := range s.Blobs {
		if !validDigest(item.Digest) || len(item.Data) > maxBlobSize || contentDigest(item.Data) != item.Digest {
			return errors.New("snapshot has an invalid blob")
		}
		if _, exists := contents[item.Digest]; exists {
			return errors.New("snapshot has duplicate blobs")
		}
		total += len(item.Data)
		if total > maxRawBytes {
			return fmt.Errorf("snapshot raw content exceeds %d bytes", maxRawBytes)
		}
		contents[item.Digest] = item.Data
	}
	used := make(map[string]bool, len(contents))
	for _, group := range [][]entry{s.HeadTree, s.Index, s.Worktree} {
		paths := make(map[string]struct{}, len(group))
		for _, item := range group {
			if err := validPath(item.Path); err != nil {
				return err
			}
			if _, exists := paths[item.Path]; exists {
				return fmt.Errorf("snapshot has duplicate path %q", item.Path)
			}
			paths[item.Path] = struct{}{}
			if item.Kind != "file" && item.Kind != "symlink" {
				return fmt.Errorf("snapshot has unsupported entry kind at %q", item.Path)
			}
			if (item.Kind == "file" && item.Mode != "100644" && item.Mode != "100755") || (item.Kind == "symlink" && item.Mode != "120000") {
				return fmt.Errorf("snapshot has invalid mode at %q", item.Path)
			}
			data, exists := contents[item.Digest]
			if !exists {
				return fmt.Errorf("snapshot entry %q references a missing blob", item.Path)
			}
			if item.Kind == "symlink" && !safeLinkTarget(string(data)) {
				return fmt.Errorf("snapshot has unsafe symlink at %q", item.Path)
			}
			used[item.Digest] = true
		}
		for path := range paths {
			for parent := filepath.ToSlash(filepath.Dir(path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
				if _, exists := paths[parent]; exists {
					return fmt.Errorf("snapshot path %q conflicts with parent %q", path, parent)
				}
			}
		}
	}
	for digest := range contents {
		if !used[digest] {
			return errors.New("snapshot has an unused blob")
		}
	}
	computedTree, err := reconstructedTreeOID(s.HeadTree, contents)
	if err != nil || computedTree != s.Head.Tree {
		return errors.New("snapshot HEAD tree entries do not match HEAD")
	}
	return nil
}

type treeNode struct {
	files map[string]entry
	dirs  map[string]*treeNode
}

func reconstructedTreeOID(entries []entry, contents map[string][]byte) (string, error) {
	root := &treeNode{files: map[string]entry{}, dirs: map[string]*treeNode{}}
	for _, item := range entries {
		node := root
		parts := strings.Split(item.Path, "/")
		for _, part := range parts[:len(parts)-1] {
			if _, exists := node.files[part]; exists {
				return "", errors.New("file conflicts with tree directory")
			}
			child := node.dirs[part]
			if child == nil {
				child = &treeNode{files: map[string]entry{}, dirs: map[string]*treeNode{}}
				node.dirs[part] = child
			}
			node = child
		}
		name := parts[len(parts)-1]
		if _, exists := node.dirs[name]; exists {
			return "", errors.New("tree directory conflicts with file")
		}
		if _, exists := node.files[name]; exists {
			return "", errors.New("duplicate tree file")
		}
		node.files[name] = item
	}
	return treeNodeOID(root, contents)
}

func treeNodeOID(node *treeNode, contents map[string][]byte) (string, error) {
	type treeItem struct {
		name string
		mode string
		oid  string
		dir  bool
	}
	items := make([]treeItem, 0, len(node.files)+len(node.dirs))
	for name, item := range node.files {
		data := contents[item.Digest]
		items = append(items, treeItem{name: name, mode: item.Mode, oid: gitObjectID("blob", data)})
	}
	for name, child := range node.dirs {
		oid, err := treeNodeOID(child, contents)
		if err != nil {
			return "", err
		}
		items = append(items, treeItem{name: name, mode: "40000", oid: oid, dir: true})
	}
	sort.Slice(items, func(left, right int) bool {
		leftName, rightName := items[left].name, items[right].name
		if items[left].dir {
			leftName += "/"
		}
		if items[right].dir {
			rightName += "/"
		}
		return leftName < rightName
	})
	var raw bytes.Buffer
	for _, item := range items {
		oid, err := hex.DecodeString(item.oid)
		if err != nil || len(oid) != sha1.Size {
			return "", errors.New("invalid reconstructed tree object")
		}
		fmt.Fprintf(&raw, "%s %s\x00", item.mode, item.name)
		raw.Write(oid)
	}
	return gitObjectID("tree", raw.Bytes()), nil
}

type limitedBuffer struct {
	data     bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	if buffer.exceeded || buffer.data.Len()+len(data) > buffer.limit {
		buffer.exceeded = true
		return len(data), nil
	}
	return buffer.data.Write(data)
}

func (buffer *limitedBuffer) Bytes() []byte { return buffer.data.Bytes() }
