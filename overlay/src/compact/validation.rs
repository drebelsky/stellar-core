//! Validation helpers for compact tx set relay messages.

/// Validate that a packed short ID blob's length is a multiple of 6.
pub fn validate_packed_short_ids(data: &[u8]) -> bool {
    data.len() % 6 == 0
}

/// Unpack a packed short ID blob into 6-byte arrays.
/// Returns None if the length is not a multiple of 6.
pub fn unpack_short_ids(data: &[u8]) -> Option<Vec<[u8; 6]>> {
    if data.len() % 6 != 0 {
        return None;
    }
    let count = data.len() / 6;
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let mut id = [0u8; 6];
        id.copy_from_slice(&data[i * 6..(i + 1) * 6]);
        result.push(id);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty() {
        assert!(validate_packed_short_ids(&[]));
    }

    #[test]
    fn test_validate_exact_multiple() {
        assert!(validate_packed_short_ids(&[0u8; 6]));
        assert!(validate_packed_short_ids(&[0u8; 12]));
        assert!(validate_packed_short_ids(&[0u8; 18]));
    }

    #[test]
    fn test_validate_not_multiple() {
        assert!(!validate_packed_short_ids(&[0u8; 1]));
        assert!(!validate_packed_short_ids(&[0u8; 5]));
        assert!(!validate_packed_short_ids(&[0u8; 7]));
    }

    #[test]
    fn test_unpack_empty() {
        let ids = unpack_short_ids(&[]).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn test_unpack_round_trip() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let ids = unpack_short_ids(&data).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], [1, 2, 3, 4, 5, 6]);
        assert_eq!(ids[1], [7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn test_unpack_invalid_length() {
        assert!(unpack_short_ids(&[0u8; 5]).is_none());
    }
}
