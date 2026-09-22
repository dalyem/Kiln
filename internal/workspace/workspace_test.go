package workspace

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCaptureAndMaterializePreserveGitViews(t *testing.T) {
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	gitTest(t, repo, "config", "user.name", "Workspace Test")
	gitTest(t, repo, "config", "user.email", "workspace@example.test")
	write(t, filepath.Join(repo, "old.txt"), []byte("old\n"), 0o644)
	write(t, filepath.Join(repo, "script.sh"), []byte("#!/bin/sh\necho base\n"), 0o755)
	gitTest(t, repo, "add", ".")
	gitTest(t, repo, "commit", "-qm", "base")
	write(t, filepath.Join(repo, "old.txt"), []byte("second\n"), 0o644)
	gitTest(t, repo, "commit", "-am", "second", "-q")

	write(t, filepath.Join(repo, "old.txt"), []byte("staged\n"), 0o644)
	gitTest(t, repo, "add", "old.txt")
	write(t, filepath.Join(repo, "old.txt"), []byte("unstaged\n"), 0o644)
	if err := os.Remove(filepath.Join(repo, "script.sh")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(repo, "untracked.bin"), []byte{0, 1, 2, 255}, 0o644)
	write(t, filepath.Join(repo, "run.sh"), []byte("#!/bin/sh\necho run\n"), 0o755)
	if err := os.Symlink("old.txt", filepath.Join(repo, "link")); err != nil {
		t.Fatal(err)
	}

	snapshot, captured, err := Capture(repo)
	if err != nil {
		t.Fatal(err)
	}
	if captured.HEAD == "" || captured.Blobs == 0 {
		t.Fatalf("unexpected capture summary: %#v", captured)
	}
	destination := filepath.Join(t.TempDir(), "materialized")
	materialized, err := Materialize(snapshot, destination)
	if err != nil {
		t.Fatal(err)
	}
	if materialized.Digest != captured.Digest {
		t.Fatalf("digest changed: %s != %s", materialized.Digest, captured.Digest)
	}
	for _, args := range [][]string{{"rev-parse", "HEAD"}, {"diff", "--raw"}, {"diff", "--cached", "--raw"}, {"ls-files", "--others", "--exclude-standard", "-z"}} {
		if got, want := gitOutput(t, destination, args...), gitOutput(t, repo, args...); !bytes.Equal(got, want) {
			t.Fatalf("git %v differs\ngot: %q\nwant: %q", args, got, want)
		}
	}
	gitTest(t, destination, "fsck", "--full")
	for _, name := range []string{"old.txt", "untracked.bin", "run.sh", "link"} {
		got, err := os.Readlink(filepath.Join(destination, name))
		if err == nil {
			want, wantErr := os.Readlink(filepath.Join(repo, name))
			if wantErr != nil || got != want {
				t.Fatalf("symlink %s: got %q, want %q", name, got, want)
			}
			continue
		}
		gotBytes, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		wantBytes, err := os.ReadFile(filepath.Join(repo, name))
		if err != nil || !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf("content %s differs", name)
		}
	}
}

func TestCaptureFileDoesNotOverwriteAndInspectRejectsDuplicateKeys(t *testing.T) {
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	gitTest(t, repo, "config", "user.name", "Workspace Test")
	gitTest(t, repo, "config", "user.email", "workspace@example.test")
	write(t, filepath.Join(repo, "file"), []byte("content"), 0o644)
	gitTest(t, repo, "add", "file")
	gitTest(t, repo, "commit", "-qm", "root")

	output := filepath.Join(t.TempDir(), "workspace.json")
	if _, err := CaptureFile(repo, output); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFile(repo, output); err == nil {
		t.Fatal("expected existing output rejection")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(append(data[:1:1], append([]byte(`"version":1,`), data[1:]...)...)); err == nil {
		t.Fatal("expected duplicate JSON key rejection")
	}
	if _, err := Inspect(bytes.Replace(data, []byte(`"version"`), []byte(`"Version"`), 1)); err == nil {
		t.Fatal("expected noncanonical JSON key rejection")
	}
	t.Setenv("GIT_CONFIG_COUNT", "1")
	if _, _, err := Capture(repo); err == nil {
		t.Fatal("expected Git configuration environment rejection")
	}
}

func TestMaterializeRejectsTamperingWithoutReplacingDestination(t *testing.T) {
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	gitTest(t, repo, "config", "user.name", "Workspace Test")
	gitTest(t, repo, "config", "user.email", "workspace@example.test")
	write(t, filepath.Join(repo, "file"), []byte("content"), 0o644)
	gitTest(t, repo, "add", "file")
	gitTest(t, repo, "commit", "-qm", "root")
	snapshot, _, err := Capture(repo)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(snapshot, []byte(`"path":"file"`), []byte(`"path":"../escape"`), 1)
	destination := filepath.Join(t.TempDir(), "destination")
	if _, err := Materialize(tampered, destination); err == nil {
		t.Fatal("expected malicious path rejection")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("materialization created output after validation failure")
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(destination, "sentinel")
	write(t, sentinel, []byte("keep"), 0o600)
	if _, err := Materialize(snapshot, destination); err == nil {
		t.Fatal("expected existing destination rejection")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("destination sentinel changed: %q, %v", got, err)
	}
}

func TestCaptureRejectsUnsafeGitDirectorySymlink(t *testing.T) {
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	gitTest(t, repo, "config", "user.name", "Workspace Test")
	gitTest(t, repo, "config", "user.email", "workspace@example.test")
	write(t, filepath.Join(repo, "file"), []byte("content"), 0o644)
	gitTest(t, repo, "add", "file")
	gitTest(t, repo, "commit", "-qm", "root")
	if err := os.Symlink(".git/config", filepath.Join(repo, "bad-link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Capture(repo); err == nil {
		t.Fatal("expected unsafe symlink rejection")
	}
}

func TestCaptureRejectsUnsupportedIndexFlags(t *testing.T) {
	for _, operation := range [][]string{{"update-index", "--skip-worktree", "file"}, {"add", "-N", "new-file"}} {
		t.Run(operation[0]+operation[1], func(t *testing.T) {
			repo := t.TempDir()
			gitTest(t, repo, "init", "-q")
			gitTest(t, repo, "config", "user.name", "Workspace Test")
			gitTest(t, repo, "config", "user.email", "workspace@example.test")
			write(t, filepath.Join(repo, "file"), []byte("content"), 0o644)
			gitTest(t, repo, "add", "file")
			gitTest(t, repo, "commit", "-qm", "root")
			if operation[0] == "add" {
				write(t, filepath.Join(repo, "new-file"), []byte("new"), 0o644)
			}
			gitTest(t, repo, operation...)
			if _, _, err := Capture(repo); err == nil {
				t.Fatal("expected unsupported index flag rejection")
			}
		})
	}
}

func gitTest(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return output
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
