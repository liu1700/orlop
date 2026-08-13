//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type chunkBatchOperation uint8

const (
	chunkBatchHas chunkBatchOperation = iota
	chunkBatchDelete
)

type chunkShard struct {
	fd   int
	path string
}

// Delete batches retain a directory descriptor so the fixed 64-character hex
// basename can be passed to unlinkat without path traversal. Presence probes
// avoid an expensive directory open on remote FUSE; their path components are
// derived entirely from the fixed-length hash, never from client path input.
func openChunkShard(path string, operation chunkBatchOperation) (*chunkShard, error) {
	if operation == chunkBatchHas {
		return &chunkShard{fd: -1, path: path}, nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &chunkShard{fd: fd}, nil
}

func closeChunkShard(shard *chunkShard) error {
	if shard.fd < 0 {
		return nil
	}
	return unix.Close(shard.fd)
}

func visitChunkShard(shard *chunkShard, name string, operation chunkBatchOperation) (bool, error) {
	switch operation {
	case chunkBatchHas:
		info, err := os.Lstat(filepath.Join(shard.path, name))
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("not a regular file")
		}
		return true, nil
	case chunkBatchDelete:
		if err := unix.Unlinkat(shard.fd, name, 0); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown chunk batch operation %d", operation)
	}
}
