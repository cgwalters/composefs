package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// crfsTOC is copied from https://github.com/containers/storage/blob/73f29956326dddf9c126465d00ec79cfb04049ae/pkg/chunked/internal/compression.go
type crfsTOC struct {
	Version int                `json:"version"`
	Entries []crfsFileMetadata `json:"entries"`
}

// crfsFileMetadata is copied from https://github.com/containers/storage/blob/73f29956326dddf9c126465d00ec79cfb04049ae/pkg/chunked/internal/compression.go
type crfsFileMetadata struct {
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Linkname   string            `json:"linkName,omitempty"`
	Mode       int64             `json:"mode,omitempty"`
	Size       int64             `json:"size"`
	UID        int               `json:"uid"`
	GID        int               `json:"gid"`
	ModTime    time.Time         `json:"modtime"`
	AccessTime time.Time         `json:"accesstime"`
	ChangeTime time.Time         `json:"changetime"`
	Devmajor   int64             `json:"devMajor"`
	Devminor   int64             `json:"devMinor"`
	Xattrs     map[string]string `json:"xattrs,omitempty"`
	Digest     string            `json:"digest,omitempty"`
	Offset     int64             `json:"offset,omitempty"`
	EndOffset  int64             `json:"endOffset,omitempty"`

	// Currently chunking is not supported.
	ChunkSize   int64  `json:"chunkSize,omitempty"`
	ChunkOffset int64  `json:"chunkOffset,omitempty"`
	ChunkDigest string `json:"chunkDigest,omitempty"`
}

func writeU32LE(w *bufio.Writer, v uint32) error {
	if err := w.WriteByte(byte(v >> 0)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(v >> 8)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(v >> 16)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(v >> 24)); err != nil {
		return err
	}
	return nil
}

func writeU64LE(w *bufio.Writer, v uint64) error {
	if err := writeU32LE(w, uint32(v)); err != nil {
		return err
	}
	if err := writeU32LE(w, uint32(v>>32)); err != nil {
		return err
	}
	return nil
}

type header struct {
	uid    uint32
	gid    uint32
	mode   uint32
	mtime  time.Time
	size   uint64
	xattrs map[string][]byte
}

func writeBytes(bufw *bufio.Writer, b []byte) error {
	if err := writeU32LE(bufw, uint32(len(b))); err != nil {
		return err
	}
	if _, err := bufw.Write([]byte(b)); err != nil {
		return err
	}
	return nil
}

func writeHeader(bufw *bufio.Writer, h header) error {

	// uid and gid
	if err := writeU32LE(bufw, h.uid); err != nil {
		return err
	}
	if err := writeU32LE(bufw, h.gid); err != nil {
		return err
	}
	// mode
	if err := writeU32LE(bufw, h.mode); err != nil {
		return err
	}
	// mtime
	if err := writeU64LE(bufw, uint64(h.mtime.Unix())); err != nil {
		return err
	}
	if err := writeU32LE(bufw, uint32(h.mtime.Nanosecond())); err != nil {
		return err
	}
	// size
	if err := writeU64LE(bufw, h.size); err != nil {
		return err
	}
	// xattrs
	if err := writeU32LE(bufw, uint32(len(h.xattrs))); err != nil {
		return err
	}
	for k, v := range h.xattrs {
		if err := writeBytes(bufw, []byte(k)); err != nil {
			return err
		}
		if err := writeBytes(bufw, v); err != nil {
			return err
		}
	}

	return nil
}

func writeChild(bufw *bufio.Writer, name string, payload []byte, entry header) error {
	// Write filename
	if err := writeBytes(bufw, []byte(name)); err != nil {
		return err
	}
	if err := writeHeader(bufw, entry); err != nil {
		return err
	}
	// Payload is actually mandatory for symlinks, but optional for regular files,
	// and must be empty for directories.
	if len(payload) > 0 {
		if err := writeBytes(bufw, payload); err != nil {
			return err
		}
	}

	return nil
}

func emitParentsFor(bufw *bufio.Writer, currentParentName *string, newParent string) error {
	if *currentParentName == newParent {
		return nil
	}
	// If we have a parent, then we need to close the directory
	if *currentParentName != "" {
		if err := writeBytes(bufw, []byte{}); err != nil {
			return err
		}
	}
	targetParent, targetName := filepath.Split(newParent)
	if targetParent != "" {
		if err := emitParentsFor(bufw, currentParentName, targetParent); err != nil {
			return err
		}
	}
	if targetName == "" {
		return fmt.Errorf("Invalid non-filepath %s", newParent)
	}

	var defaultDirHeader header
	defaultDirHeader.mode = 0o755 | 0x4000

	if err := writeHeader(bufw, defaultDirHeader); err != nil {
		return err
	}

	*currentParentName = newParent

	return nil
}

func run() error {
	output := os.Args[1]

	inputBuf, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var toc crfsTOC
	if err := json.Unmarshal(inputBuf, &toc); err != nil {
		return fmt.Errorf("failed to parse input: %w", err)
	}

	cmd := exec.Command("mkcomposefs", "-", output)
	piper, pipew, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdin = piper
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	piper.Close()
	w := bufio.NewWriter(pipew)

	currentParent := ""
	for _, entry := range toc.Entries {
		switch entry.Type {
		case "reg":
		case "symlink":
		case "dir":
			break
		default:
			return fmt.Errorf("unknown type %s", entry.Type)
		}
		var h header
		h.uid = uint32(entry.UID)
		h.gid = uint32(entry.GID)
		h.size = uint64(entry.Size)
		h.mode = uint32(entry.Mode)
		h.mtime = entry.ModTime

		parent, name := filepath.Split(entry.Name)
		if err := emitParentsFor(w, &currentParent, parent); err != nil {
			return err
		}

		if err := writeChild(w, name, []byte(entry.Linkname), h); err != nil {
			return err
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}
	pipew.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("failed to wait for child: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
