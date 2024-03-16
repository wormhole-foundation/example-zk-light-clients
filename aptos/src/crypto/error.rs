// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Failed to deserialize a valid BLS signature from received bytes")]
    SignatureDeserializationError,
    #[error("Failed to deserialize a valid public key from received bytes")]
    PublicKeyDeserializationError,
}
