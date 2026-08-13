//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
)

type chunkBatchOperation uint8

const (
	chunkBatchHas chunkBatchOperation = iota
	chunkBatchDelete
)

type chunkShard struct {
	root *os.Root
}

func openChunkShard(path string, _ chunkBatchOperation) (*chunkShard, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &chunkShard{root: root}, nil
}

func closeChunkShard(shard *chunkShard) error {
	return shard.root.Close()
}

func visitChunkShard(shard *chunkShard, name string, operation chunkBatchOperation) (bool, error) {
	switch operation {
	case chunkBatchHas:
		info, err := shard.root.Lstat(name)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("not a regular file")
		}
		return true, nil
	case chunkBatchDelete:
		info, err := shard.root.Lstat(name)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if info.IsDir() {
			return false, fmt.Errorf("chunk entry is a directory")
		}
		if err := shard.root.Remove(name); err != nil {
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
