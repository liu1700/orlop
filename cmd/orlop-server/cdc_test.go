package main

import (
	"bytes"
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lukechampine.com/blake3"
)

func TestChunkReaderRoundTrip(t *testing.T) {
	// 16 MiB of deterministic pseudo-random data: large enough that FastCDC
	// reliably produces ≥2 chunks, and seeded so the boundary count is stable
	// run-to-run instead of probabilistic with crypto/rand.
	data := make([]byte, 16*1024*1024)
	rng := mrand.New(mrand.NewSource(42))
	if _, err := rng.Read(data); err != nil {
		t.Fatal(err)
	}
	chunks, err := ChunkReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected ≥2 chunks for 6 MiB, got %d", len(chunks))
	}
	// Concatenated chunks must reconstruct the input.
	var sum int
	for _, c := range chunks {
		sum += len(c.Bytes)
	}
	if sum != len(data) {
		t.Fatalf("chunk total = %d, want %d", sum, len(data))
	}
	rebuilt := make([]byte, 0, len(data))
	for _, c := range chunks {
		rebuilt = append(rebuilt, c.Bytes...)
	}
	if !bytes.Equal(rebuilt, data) {
		t.Fatalf("rebuilt content does not match original")
	}
	// Offsets are monotonic and contiguous.
	var nextOff uint64
	for i, c := range chunks {
		if c.Offset != nextOff {
			t.Fatalf("chunk %d offset=%d, want %d", i, c.Offset, nextOff)
		}
		nextOff += uint64(c.Len)
	}
}

func TestChunkReaderEmptyFile(t *testing.T) {
	chunks, err := ChunkReader(bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || chunks[0].Len != 0 {
		t.Fatalf("expected one zero-length chunk, got %+v", chunks)
	}
}

func TestChunkFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	data := bytes.Repeat([]byte("abcdefghij"), 256*1024) // 2.5 MiB
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	chunks, err := ChunkFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := make([]byte, 0, len(data))
	for _, c := range chunks {
		rebuilt = append(rebuilt, c.Bytes...)
	}
	if !bytes.Equal(rebuilt, data) {
		t.Fatalf("round-trip failed for %d bytes", len(data))
	}
}

// TestFastCDC4MiBGoldenVector verifies that the Go FastCDC v2020 implementation
// produces the same chunk boundaries and BLAKE3 hashes as the Rust client for
// a fixed 4 MiB pseudo-random input. Both sides write a snapshot on first run;
// subsequent runs assert against it. Run `diff fastcdc_chunks_rust.txt
// fastcdc_chunks_go.txt` to confirm cross-language parity.
func TestFastCDC4MiBGoldenVector(t *testing.T) {
	data, err := os.ReadFile("../../tests/golden/fastcdc_vector.bin")
	if err != nil {
		t.Skip("golden vector not present — run: head -c 4194304 /dev/urandom > tests/golden/fastcdc_vector.bin")
	}

	chunks, err := ChunkReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	for _, c := range chunks {
		h := blake3.Sum256(c.Bytes)
		fmt.Fprintf(&b, "%d %d %x", c.Offset, c.Len, h[:])
		fmt.Fprint(&b, "\n")
	}
	// Strip trailing newline to match Rust format (join("\n") has none).
	got := strings.TrimRight(b.String(), "\n")

	snapPath := "../../tests/golden/fastcdc_chunks_go.txt"
	if _, err := os.Stat(snapPath); errors.Is(err, os.ErrNotExist) {
		if werr := os.WriteFile(snapPath, []byte(got), 0o644); werr != nil {
			t.Fatalf("cannot write snapshot: %v", werr)
		}
		t.Logf("wrote Go snapshot: %s", snapPath)
		return
	}

	want, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("chunk vector mismatch:\nwant (first 500 chars):\n%.500s\ngot (first 500 chars):\n%.500s", want, got)
	}
}

// FastCDC's product win: a single byte change near the start should leave
// most chunks unchanged. Deterministic seed + 16 MiB so FastCDC reliably
// produces multiple chunks; otherwise a single-chunk corpus has zero overlap
// after the byte insert and the test flakes.
func TestChunkReaderInsertNearStartReusesChunks(t *testing.T) {
	base := make([]byte, 16*1024*1024)
	rng := mrand.New(mrand.NewSource(7))
	if _, err := rng.Read(base); err != nil {
		t.Fatal(err)
	}
	// Insert one byte at offset 1024.
	mutated := make([]byte, 0, len(base)+1)
	mutated = append(mutated, base[:1024]...)
	mutated = append(mutated, 0x42)
	mutated = append(mutated, base[1024:]...)

	a, _ := ChunkReader(bytes.NewReader(base))
	b, _ := ChunkReader(bytes.NewReader(mutated))

	hashes := map[[HashLen]byte]struct{}{}
	for _, c := range a {
		hashes[c.Hash] = struct{}{}
	}
	overlap := 0
	for _, c := range b {
		if _, ok := hashes[c.Hash]; ok {
			overlap++
		}
	}
	if overlap == 0 {
		t.Fatalf("FastCDC produced zero overlap between near-identical files")
	}
}
