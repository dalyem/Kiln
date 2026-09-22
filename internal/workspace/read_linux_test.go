//go:build linux

package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCaptureNestedFilesDoesNotLeakDescriptors(t *testing.T) {
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	gitTest(t, repo, "config", "user.name", "Workspace Test")
	gitTest(t, repo, "config", "user.email", "workspace@example.test")
	directory := repo
	for _, part := range []string{"one", "two", "three", "four"} {
		directory = filepath.Join(directory, part)
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(directory, "file"), []byte("content"), 0o644)
	gitTest(t, repo, "add", ".")
	gitTest(t, repo, "commit", "-qm", "root")
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 10; index++ {
		if _, _, err := Capture(repo); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+1 {
		t.Fatalf("capture leaked file descriptors: before=%d after=%d", len(before), len(after))
	}
}

func TestInspectFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := InspectFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected FIFO rejection")
		}
	case <-time.After(time.Second):
		t.Fatal("InspectFile blocked on FIFO")
	}
}
