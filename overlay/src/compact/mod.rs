pub mod short_id;
pub mod resolver;
pub mod validation;

use crate::integrated::OverlayHandle;

/// Extract all packed short IDs from a CompactTransactionSet XDR body
/// (everything after txSetHash[32] + nonce[8]).
///
/// The body contains `phases[2]` — a fixed XDR array of 2 CompactTransactionPhase unions.
/// Returns a flat list of all 6-byte short IDs in positional order.
pub fn extract_all_short_ids(phases_data: &[u8]) -> Result<Vec<[u8; 6]>, String> {
    let mut offset = 0;
    let mut all_ids = Vec::new();

    // Two phases: CLASSIC (0) and SOROBAN (1)
    for phase_idx in 0..2 {
        if offset + 4 > phases_data.len() {
            return Err(format!("phase {} truncated at discriminant", phase_idx));
        }
        let discriminant = read_u32_be(phases_data, &mut offset);

        match discriminant {
            0 => {
                // Sequential: v0Components<> — XDR variable-length array
                if offset + 4 > phases_data.len() {
                    return Err(format!("phase {} sequential: truncated at component count", phase_idx));
                }
                let component_count = read_u32_be(phases_data, &mut offset) as usize;
                for comp_idx in 0..component_count {
                    // baseFee: int64* (optional pointer: 4-byte bool, optionally followed by 8-byte int64)
                    skip_optional_int64(phases_data, &mut offset)
                        .map_err(|e| format!("phase {} comp {}: {}", phase_idx, comp_idx, e))?;

                    // shortTxIds: PackedShortTxIds (opaque<>)
                    let ids = read_packed_short_ids(phases_data, &mut offset)
                        .map_err(|e| format!("phase {} comp {}: {}", phase_idx, comp_idx, e))?;
                    all_ids.extend(ids);
                }
            }
            1 => {
                // Parallel: CompactParallelTxsComponent
                // baseFee: int64*
                skip_optional_int64(phases_data, &mut offset)
                    .map_err(|e| format!("phase {} parallel baseFee: {}", phase_idx, e))?;

                // executionStages<>: variable array of CompactParallelTxExecutionStage
                if offset + 4 > phases_data.len() {
                    return Err(format!("phase {} parallel: truncated at stage count", phase_idx));
                }
                let stage_count = read_u32_be(phases_data, &mut offset) as usize;
                for stage_idx in 0..stage_count {
                    // Each stage is CompactDependentTxCluster<> — array of PackedShortTxIds
                    if offset + 4 > phases_data.len() {
                        return Err(format!("phase {} stage {}: truncated at cluster count", phase_idx, stage_idx));
                    }
                    let cluster_count = read_u32_be(phases_data, &mut offset) as usize;
                    for cluster_idx in 0..cluster_count {
                        let ids = read_packed_short_ids(phases_data, &mut offset)
                            .map_err(|e| format!("phase {} stage {} cluster {}: {}",
                                phase_idx, stage_idx, cluster_idx, e))?;
                        all_ids.extend(ids);
                    }
                }
            }
            other => {
                return Err(format!("phase {} unknown discriminant {}", phase_idx, other));
            }
        }
    }

    Ok(all_ids)
}

/// Resolve short IDs against the mempool via the OverlayHandle.
pub async fn resolve_against_mempool(
    overlay_handle: &OverlayHandle,
    tx_set_hash: &[u8; 32],
    nonce: u64,
    short_ids: &[[u8; 6]],
) -> Vec<(u8, Vec<u8>)> {
    overlay_handle
        .resolve_short_ids(*tx_set_hash, nonce, short_ids.to_vec())
        .await
}

fn read_u32_be(data: &[u8], offset: &mut usize) -> u32 {
    let val = u32::from_be_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    val
}

/// Skip an XDR optional int64 (int64*): 4-byte bool, then conditionally 8 bytes.
fn skip_optional_int64(data: &[u8], offset: &mut usize) -> Result<(), String> {
    if *offset + 4 > data.len() {
        return Err("truncated at optional int64 flag".to_string());
    }
    let present = read_u32_be(data, offset);
    if present != 0 {
        if *offset + 8 > data.len() {
            return Err("truncated at optional int64 value".to_string());
        }
        *offset += 8;
    }
    Ok(())
}

/// Read an XDR opaque<> (PackedShortTxIds) and unpack into 6-byte arrays.
fn read_packed_short_ids(data: &[u8], offset: &mut usize) -> Result<Vec<[u8; 6]>, String> {
    if *offset + 4 > data.len() {
        return Err("truncated at opaque length".to_string());
    }
    let len = read_u32_be(data, offset) as usize;
    if *offset + len > data.len() {
        return Err(format!("opaque data truncated: need {} have {}", len, data.len() - *offset));
    }
    if len % 6 != 0 {
        return Err(format!("packed short IDs length {} not multiple of 6", len));
    }

    let blob = &data[*offset..*offset + len];
    *offset += len;
    // XDR pads opaque to 4-byte boundary
    let padding = (4 - (len % 4)) % 4;
    *offset += padding;

    validation::unpack_short_ids(blob)
        .ok_or_else(|| "unpack failed".to_string())
}
