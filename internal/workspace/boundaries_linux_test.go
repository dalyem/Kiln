//go:build linux

package workspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBoundaryRejectsHostileSnapshotsBeforePublishing(t *testing.T) {
	repo := boundaryRepo(t)
	if err := os.Symlink("file", filepath.Join(repo, "link")); err != nil {
		t.Fatal(err)
	}
	raw, _, err := Capture(repo)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*snapshot)
		data   func() []byte
	}{
		{name: "path traversal", mutate: func(value *snapshot) { value.Worktree[0].Path = "../escape" }},
		{name: "git path", mutate: func(value *snapshot) { value.Worktree[0].Path = ".git/config" }},
		{name: "parent conflict", mutate: func(value *snapshot) {
			value.Worktree = append(value.Worktree, entry{Path: "file/child", Mode: "100644", Digest: value.Worktree[0].Digest, Kind: "file"})
		}},
		{name: "missing digest", mutate: func(value *snapshot) { value.Worktree[0].Digest = strings.Repeat("0", 64) }},
		{name: "tree mismatch", mutate: func(value *snapshot) { value.Head.Tree = strings.Repeat("0", 40) }},
		{name: "unsafe link", mutate: func(value *snapshot) {
			for _, item := range value.Worktree {
				if item.Kind != "symlink" {
					continue
				}
				for index := range value.Blobs {
					if value.Blobs[index].Digest == item.Digest {
						value.Blobs[index].Data = []byte("../outside")
						value.Blobs[index].Digest = contentDigest(value.Blobs[index].Data)
						for entryIndex := range value.Worktree {
							if value.Worktree[entryIndex].Path == item.Path {
								value.Worktree[entryIndex].Digest = value.Blobs[index].Digest
							}
						}
					}
				}
			}
		}},
		{name: "unknown key", data: func() []byte { return append([]byte(`{"unknown":true,`), raw[1:]...) }},
		{name: "trailing JSON", data: func() []byte { return append(append([]byte{}, raw...), []byte("null")...) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var data []byte
			if test.data != nil {
				data = test.data()
			} else {
				value := decodeBoundarySnapshot(t, raw)
				test.mutate(&value)
				data = encodeBoundarySnapshot(t, value)
			}
			if _, err := Inspect(data); err == nil {
				t.Fatal("Inspect accepted hostile snapshot")
			}
			destination := filepath.Join(t.TempDir(), "destination")
			if _, err := Materialize(data, destination); err == nil {
				t.Fatal("Materialize accepted hostile snapshot")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("hostile snapshot published a destination")
			}
		})
	}
}

func TestBoundaryCaptureRejectsSizeAndEntryLimits(t *testing.T) {
	t.Run("oversized file", func(t *testing.T) {
		repo := boundaryRepo(t)
		path := filepath.Join(repo, "large")
		write(t, path, nil, 0o600)
		if err := os.Truncate(path, maxBlobSize+1); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Capture(repo); err == nil {
			t.Fatal("Capture accepted a file over the blob limit")
		}
	})
	t.Run("raw aggregate", func(t *testing.T) {
		repo := boundaryRepo(t)
		for index := 0; index < 4; index++ {
			path := filepath.Join(repo, fmt.Sprintf("large-%d", index))
			if err := os.WriteFile(path, []byte{byte(index + 1)}, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, maxBlobSize); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := Capture(repo); err == nil {
			t.Fatal("Capture accepted raw content over the aggregate limit")
		}
	})
	t.Run("entry count", func(t *testing.T) {
		repo := boundaryRepo(t)
		for index := 0; index < maxEntries; index++ {
			if err := os.WriteFile(filepath.Join(repo, fmt.Sprintf("entry-%05d", index)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := Capture(repo); err == nil {
			t.Fatal("Capture accepted more than the entry limit")
		}
	})
}

func TestBoundaryInspectRejectsOversizedInputBeforeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-snapshot")
	write(t, path, nil, 0o600)
	if err := os.Truncate(path, maxSnapshotSize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectFile(path); err == nil {
		t.Fatal("InspectFile accepted an oversized input")
	}
}

func TestBoundaryRejectsLFSHeadOnlyAndAllowsLFilename(t *testing.T) {
	t.Run("HEAD only LFS pointer", func(t *testing.T) {
		repo := boundaryRepoWithFile(t, "pointer", []byte("version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\n"))
		if err := os.Remove(filepath.Join(repo, "pointer")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Capture(repo); err == nil {
			t.Fatal("Capture accepted a HEAD-only LFS pointer")
		}
	})
	t.Run("ordinary lfs filename", func(t *testing.T) {
		repo := boundaryRepoWithFile(t, "lfs", []byte("ordinary content\n"))
		if _, _, err := Capture(repo); err != nil {
			t.Fatalf("Capture rejected ordinary lfs filename: %v", err)
		}
	})
}

func TestBoundaryMaterializeSuppressesGlobalHooksAndFsmonitor(t *testing.T) {
	repo := boundaryRepo(t)
	raw, _, err := Capture(repo)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	sentinel := filepath.Join(directory, "executed")
	hooks := filepath.Join(directory, "hooks")
	if err := os.Mkdir(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "script")
	write(t, script, []byte("#!/bin/sh\ntouch "+strconv.Quote(sentinel)+"\n"), 0o700)
	write(t, filepath.Join(hooks, "reference-transaction"), []byte("#!/bin/sh\ntouch "+strconv.Quote(sentinel)+"\n"), 0o700)
	global := filepath.Join(directory, "gitconfig")
	write(t, global, []byte("[core]\n\thooksPath = "+hooks+"\n\tfsmonitor = "+script+"\n"), 0o600)
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	if _, err := Materialize(raw, filepath.Join(t.TempDir(), "destination")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("materialization executed a global Git hook or fsmonitor")
	}
}

func TestBoundaryCaptureDetectsMutationBetweenObservations(t *testing.T) {
	repo := boundaryRepo(t)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	marker := filepath.Join(directory, "mutated")
	wrapper := filepath.Join(directory, "git")
	source := filepath.Join(repo, "file")
	script := "#!/bin/sh\nfor argument in \"$@\"; do\n  if [ \"$argument\" = check-attr ] && [ ! -e " + strconv.Quote(marker) + " ]; then\n    printf 'changed\\n' > " + strconv.Quote(source) + "\n    : > " + strconv.Quote(marker) + "\n  fi\ndone\nexec " + strconv.Quote(realGit) + " \"$@\"\n"
	write(t, wrapper, []byte(script), 0o700)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	output := filepath.Join(t.TempDir(), "snapshot")
	if _, err := CaptureFile(repo, output); err == nil {
		t.Fatal("CaptureFile accepted a repository changed between observations")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("CaptureFile published output after an observed mutation")
	}
}

func TestBoundaryCaptureRejectsWrongGitBlobBytes(t *testing.T) {
	repo := boundaryRepoWithFile(t, "file", []byte("content\n"))
	write(t, filepath.Join(repo, "indexonly"), []byte("indexed\n"), 0o644)
	gitTest(t, repo, "add", "indexonly")
	oid := strings.TrimSpace(string(gitOutput(t, repo, "rev-parse", ":indexonly")))
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	wrapper := filepath.Join(directory, "git")
	script := "#!/bin/sh\ncase \" $* \" in\n  *\" cat-file blob " + oid + "\"*) printf 'changed\\n'; exit 0 ;;\nesac\nexec " + strconv.Quote(realGit) + " \"$@\"\n"
	write(t, wrapper, []byte(script), 0o700)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, _, err := Capture(repo); err == nil {
		t.Fatal("Capture accepted bytes that did not match the requested Git blob")
	}
}

func TestBoundaryPreservesNativeTreeOrder(t *testing.T) {
	repo := boundaryRepo(t)
	if err := os.Mkdir(filepath.Join(repo, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(repo, "a", "inside"), []byte("inside\n"), 0o644)
	write(t, filepath.Join(repo, "a.txt"), []byte("outside\n"), 0o644)
	gitTest(t, repo, "add", ".")
	gitTest(t, repo, "commit", "-qm", "nested")
	raw, _, err := Capture(repo)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	if _, err := Materialize(raw, destination); err != nil {
		t.Fatal(err)
	}
	if got, want := gitOutput(t, destination, "rev-parse", "HEAD^{tree}"), gitOutput(t, repo, "rev-parse", "HEAD^{tree}"); !bytes.Equal(got, want) {
		t.Fatalf("native tree order changed: got %q want %q", got, want)
	}
}

func boundaryRepo(t *testing.T) string { return boundaryRepoWithFile(t, "file", []byte("content\n")) }

func boundaryRepoWithFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	gitTest(t, repo, "config", "user.name", "Workspace Test")
	gitTest(t, repo, "config", "user.email", "workspace@example.test")
	write(t, filepath.Join(repo, name), data, 0o644)
	gitTest(t, repo, "add", ".")
	gitTest(t, repo, "commit", "-qm", "root")
	return repo
}

func decodeBoundarySnapshot(t *testing.T, data []byte) snapshot {
	t.Helper()
	var value snapshot
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func encodeBoundarySnapshot(t *testing.T, value snapshot) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
