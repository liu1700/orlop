//! FastCDC parity test: identical input → identical chunk boundaries + BLAKE3 hashes
//! on the Rust client and the Go server.
//!
//! The golden vector (tests/golden/fastcdc_vector.bin) is 4 MiB of pseudo-random
//! bytes. Both sides snapshot their chunk list (offset length hash) to
//! tests/golden/fastcdc_chunks_rust.txt and tests/golden/fastcdc_chunks_go.txt
//! on the first run, then assert identical content on subsequent runs.
//! A `diff` of the two snapshots proves algorithm parity.

use blake3::Hasher;
use orlop::write_handle::{CHUNK_AVG, CHUNK_MAX, CHUNK_MIN};

const VECTOR_PATH: &str = "tests/golden/fastcdc_vector.bin";
const SNAP_PATH: &str = "tests/golden/fastcdc_chunks_rust.txt";

#[test]
fn fastcdc_4mib_golden_vector_chunks() {
    let bytes = match std::fs::read(VECTOR_PATH) {
        Ok(b) => b,
        Err(e) => panic!("golden vector not found at {VECTOR_PATH}: {e}\nRun: head -c 4194304 /dev/urandom > {VECTOR_PATH}"),
    };

    let chunks: Vec<(usize, usize, String)> =
        fastcdc::v2020::FastCDC::new(&bytes, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX)
            .map(|c| {
                let mut h = Hasher::new();
                h.update(&bytes[c.offset..c.offset + c.length]);
                (c.offset, c.length, hex::encode(h.finalize().as_bytes()))
            })
            .collect();

    assert!(!chunks.is_empty(), "no chunks produced from 4 MiB input");

    // Format: one line per chunk: "<offset> <length> <hash>"
    // No trailing newline — matches Go snapshot format (trimmed there too).
    let actual = chunks
        .iter()
        .map(|(o, l, h)| format!("{o} {l} {h}"))
        .collect::<Vec<_>>()
        .join("\n");

    if !std::path::Path::new(SNAP_PATH).exists() {
        std::fs::write(SNAP_PATH, &actual)
            .unwrap_or_else(|e| panic!("cannot write snapshot {SNAP_PATH}: {e}"));
        eprintln!("wrote Rust snapshot: {SNAP_PATH}");
        return;
    }

    let want = std::fs::read_to_string(SNAP_PATH)
        .unwrap_or_else(|e| panic!("cannot read snapshot {SNAP_PATH}: {e}"));
    assert_eq!(
        want, actual,
        "chunk snapshot mismatch — re-run with snapshot deleted to regenerate"
    );
}
