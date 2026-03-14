use cesr::{Digest, Matter};

/// Compute the revocation hash for a credential SAID.
/// `revocation_hash = Blake3(credential_said.as_bytes()).qb64()`
pub fn revocation_hash(credential_said: &str) -> String {
    let bytes = [b"kels/revocation:", credential_said.as_bytes()].concat();
    Digest::blake3_256(&bytes).qb64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_hash_deterministic() {
        let said = "EAbc1234567890123456789012345678901234567890";
        let h1 = revocation_hash(said);
        let h2 = revocation_hash(said);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_revocation_hash_length() {
        let said = "EAbc1234567890123456789012345678901234567890";
        let hash = revocation_hash(said);
        assert_eq!(hash.len(), 44);
    }

    #[test]
    fn test_revocation_hash_differs_from_said() {
        let said = "EAbc1234567890123456789012345678901234567890";
        let hash = revocation_hash(said);
        assert_ne!(hash, said);
    }

    #[test]
    fn test_revocation_hash_different_inputs() {
        let h1 = revocation_hash("EAbc1234567890123456789012345678901234567890");
        let h2 = revocation_hash("EXyz1234567890123456789012345678901234567890");
        assert_ne!(h1, h2);
    }
}
