//go:build linux

package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func materialize(s snapshot, destination string) (result error) {
	if !filepath.IsAbs(destination) {
		return errors.New("--destination must be an absolute path")
	}
	destination = filepath.Clean(destination)
	parent, name := filepath.Dir(destination), filepath.Base(destination)
	if name == "." || name == string(filepath.Separator) {
		return errors.New("invalid destination")
	}
	if err := trustedPrivateDirectory(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check destination: %w", err)
	}
	stage, err := os.MkdirTemp(parent, ".kiln-workspace-")
	if err != nil {
		return fmt.Errorf("create private staging directory: %w", err)
	}
	defer func() {
		if result != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, 0o700); err != nil {
		return err
	}
	if err := rebuildGit(s, stage); err != nil {
		return err
	}
	if err := writeWorktree(s, stage); err != nil {
		return err
	}
	if _, err := gitStage(stage, nil, nil, "fsck", "--full"); err != nil {
		return errors.New("reconstructed Git repository failed fsck")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("destination already exists")
		}
		return fmt.Errorf("publish workspace: %w", err)
	}
	return nil
}

func trustedPrivateDirectory(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("destination parent: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("destination parent has a symlink or is not a directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("destination parent has no ownership metadata")
		}
		if current == path {
			if int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
				return errors.New("destination parent must be owned and not writable by group or others")
			}
		} else if int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid() {
			return errors.New("destination ancestor must be owned by root or the current user")
		} else if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("destination ancestor is writable without a sticky bit")
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func trustedOutputDirectory(path string) error { return trustedPrivateDirectory(path) }

func rebuildGit(s snapshot, stage string) error {
	if _, err := gitStage(stage, nil, nil, "init", "--quiet", "--template=/dev/null"); err != nil {
		return errors.New("initialize reconstructed Git repository")
	}
	oids := make(map[string]string, len(s.Blobs))
	for _, item := range s.Blobs {
		output, err := gitStage(stage, nil, item.Data, "hash-object", "-w", "--no-filters", "--stdin")
		if err != nil {
			return errors.New("write reconstructed Git blob")
		}
		oid := strings.TrimSpace(string(output))
		if !validOID(oid) {
			return errors.New("Git returned an invalid reconstructed blob ID")
		}
		oids[item.Digest] = oid
	}
	headIndex := filepath.Join(stage, ".git", "kiln-head-index")
	if err := writeIndex(stage, headIndex, s.HeadTree, oids); err != nil {
		return err
	}
	tree, err := gitStage(stage, []string{"GIT_INDEX_FILE=" + headIndex}, nil, "write-tree")
	if err != nil || strings.TrimSpace(string(tree)) != s.Head.Tree {
		return errors.New("reconstructed HEAD tree did not match snapshot")
	}
	commit, err := gitStage(stage, nil, s.Head.Commit, "hash-object", "-w", "-t", "commit", "--stdin")
	if err != nil || strings.TrimSpace(string(commit)) != s.Head.OID {
		return errors.New("reconstructed HEAD commit did not match snapshot")
	}
	_, parents, err := parseCommit(s.Head.Commit)
	if err != nil {
		return errors.New("read reconstructed HEAD commit")
	}
	if len(parents) > 0 {
		if err := os.WriteFile(filepath.Join(stage, ".git", "shallow"), []byte(s.Head.OID+"\n"), 0o600); err != nil {
			return fmt.Errorf("write shallow marker: %w", err)
		}
	}
	if _, err := gitStage(stage, nil, nil, "update-ref", "--no-deref", "HEAD", s.Head.OID); err != nil {
		return errors.New("set detached reconstructed HEAD")
	}
	if err := writeIndex(stage, filepath.Join(stage, ".git", "index"), s.Index, oids); err != nil {
		return err
	}
	_ = os.Remove(headIndex)
	return nil
}

func writeIndex(stage, indexPath string, entries []entry, oids map[string]string) error {
	var input bytes.Buffer
	for _, item := range entries {
		oid, exists := oids[item.Digest]
		if !exists {
			return errors.New("snapshot index references a missing blob")
		}
		fmt.Fprintf(&input, "%s %s\t%s\x00", item.Mode, oid, item.Path)
	}
	if _, err := gitStage(stage, []string{"GIT_INDEX_FILE=" + indexPath}, nil, "read-tree", "--empty"); err != nil {
		return errors.New("initialize reconstructed Git index")
	}
	if len(entries) == 0 {
		return nil
	}
	if _, err := gitStage(stage, []string{"GIT_INDEX_FILE=" + indexPath}, input.Bytes(), "update-index", "-z", "--index-info"); err != nil {
		return errors.New("write reconstructed Git index")
	}
	return nil
}

func gitStage(directory string, additions []string, input []byte, args ...string) ([]byte, error) {
	context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fixed := []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.useReplaceRefs=false", "-c", "core.fileMode=true", "-c", "core.bare=false", "-c", "protocol.allow=never", "-c", "protocol.file.allow=never", "-c", "protocol.ssh.allow=never", "-c", "protocol.git.allow=never", "-c", "protocol.http.allow=never", "-c", "protocol.https.allow=never", "-c", "protocol.ext.allow=never"}
	fixed = append(fixed, args...)
	command := exec.CommandContext(context, "git", fixed...)
	command.Dir = directory
	command.Env = append(cleanEnv(), append([]string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}, additions...)...)
	command.Stdin = bytes.NewReader(input)
	var output limitedBuffer
	output.limit = maxSnapshotSize
	command.Stdout = &output
	if err := command.Run(); err != nil {
		if context.Err() != nil {
			return nil, errors.New("Git command timed out")
		}
		return nil, err
	}
	if output.exceeded {
		return nil, errors.New("Git command output exceeds snapshot limit")
	}
	return output.Bytes(), nil
}

func writeWorktree(s snapshot, stage string) error {
	contents := make(map[string][]byte, len(s.Blobs))
	for _, item := range s.Blobs {
		contents[item.Digest] = item.Data
	}
	for _, item := range s.Worktree {
		if err := writeWorktreeEntry(stage, item, contents[item.Digest]); err != nil {
			return err
		}
	}
	return nil
}

func writeWorktreeEntry(stage string, item entry, data []byte) error {
	parent := stage
	parts := strings.Split(item.Path, "/")
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		if err := mkdirPrivate(parent); err != nil {
			return fmt.Errorf("create parent for %q: %w", item.Path, err)
		}
	}
	path := filepath.Join(parent, parts[len(parts)-1])
	if item.Kind == "symlink" {
		if err := os.Symlink(string(data), path); err != nil {
			return fmt.Errorf("write symlink %q: %w", item.Path, err)
		}
		return nil
	}
	file, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, uint32(modePerm(item.Mode)))
	if err != nil {
		return fmt.Errorf("create worktree file %q: %w", item.Path, err)
	}
	defer unix.Close(file)
	if err := unix.Fchmod(file, uint32(modePerm(item.Mode))); err != nil {
		return fmt.Errorf("set worktree file mode %q: %w", item.Path, err)
	}
	for len(data) > 0 {
		written, err := unix.Write(file, data)
		if err != nil {
			return fmt.Errorf("write worktree file %q: %w", item.Path, err)
		}
		data = data[written:]
	}
	return nil
}

func mkdirPrivate(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		return errors.New("path is not a real directory")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Mkdir(path, 0o700)
}

func modePerm(mode string) os.FileMode {
	if mode == "100755" {
		return 0o755
	}
	return 0o644
}
