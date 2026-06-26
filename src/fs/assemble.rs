use crate::store::Manifest;

/// Slice the byte range [offset, offset+size) from a manifest's chunk list,
/// fetching all needed chunks in one batch via `fetch_chunks`. Used by FUSE
/// read on write handles. `size = 0` means "from `offset` to EOF".
///
/// `fetch_chunks` receives the unique-ordered list of hashes the slice needs
/// and returns their bytes in the same order. Batching at this layer lets
/// `DataStore` issue parallel chunk_get RPCs instead of one per chunk.
#[allow(dead_code)] // wired in Task 23
pub(crate) fn assemble_range<F>(
    mf: &Manifest,
    offset: u64,
    size: u32,
    fetch_chunks: F,
) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(&[[u8; 32]]) -> anyhow::Result<Vec<Vec<u8>>>,
{
    let end = if size == 0 {
        mf.size
    } else {
        offset.saturating_add(size as u64).min(mf.size)
    };
    if offset >= end {
        return Ok(Vec::new());
    }

    // Collect distinct in-range hashes preserving manifest order so the
    // backend can pipeline them; map each hash to its index for slicing.
    let mut needed: Vec<[u8; 32]> = Vec::new();
    let mut hash_index: std::collections::HashMap<[u8; 32], usize> =
        std::collections::HashMap::new();
    for chunk in &mf.chunks {
        let chunk_end = chunk.offset + chunk.len as u64;
        if chunk_end <= offset {
            continue;
        }
        if chunk.offset >= end {
            break;
        }
        if let std::collections::hash_map::Entry::Vacant(e) = hash_index.entry(chunk.hash) {
            e.insert(needed.len());
            needed.push(chunk.hash);
        }
    }
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let fetched = fetch_chunks(&needed)?;
    if fetched.len() != needed.len() {
        anyhow::bail!(
            "fetch_chunks returned {} bytes for {} hashes",
            fetched.len(),
            needed.len()
        );
    }

    let mut out = Vec::with_capacity((end - offset) as usize);
    for chunk in &mf.chunks {
        let chunk_end = chunk.offset + chunk.len as u64;
        if chunk_end <= offset {
            continue;
        }
        if chunk.offset >= end {
            break;
        }
        let idx = hash_index[&chunk.hash];
        let bytes = &fetched[idx];
        let slice_start = offset.saturating_sub(chunk.offset) as usize;
        let slice_end = (end - chunk.offset).min(chunk.len as u64) as usize;
        out.extend_from_slice(&bytes[slice_start..slice_end]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ChunkRef;

    fn h(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn slices_across_two_chunks() {
        let mf = Manifest {
            size: 20,
            mode: 0,
            mtime_ns: 0,
            version: 1,
            chunks: vec![
                ChunkRef {
                    hash: h(1),
                    offset: 0,
                    len: 10,
                },
                ChunkRef {
                    hash: h(2),
                    offset: 10,
                    len: 10,
                },
            ],
        };
        let got = assemble_range(&mf, 5, 10, |hashes| {
            Ok(hashes
                .iter()
                .map(|hash| {
                    if hash[0] == 1 {
                        (0u8..10).collect()
                    } else {
                        (10u8..20).collect()
                    }
                })
                .collect())
        })
        .unwrap();
        assert_eq!(got, vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    }

    #[test]
    fn empty_when_offset_past_end() {
        let mf = Manifest {
            size: 5,
            ..Default::default()
        };
        let got = assemble_range(&mf, 10, 100, |_| panic!("should not fetch")).unwrap();
        assert_eq!(got, Vec::<u8>::new());
    }

    #[test]
    fn size_zero_reads_to_eof() {
        let mf = Manifest {
            size: 6,
            mode: 0,
            mtime_ns: 0,
            version: 1,
            chunks: vec![ChunkRef {
                hash: h(1),
                offset: 0,
                len: 6,
            }],
        };
        let got = assemble_range(&mf, 2, 0, |_| Ok(vec![b"ABCDEF".to_vec()])).unwrap();
        assert_eq!(got, b"CDEF");
    }
}
