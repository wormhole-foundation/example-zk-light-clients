// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use thiserror::Error;

/// Errors possible during signature verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiError {
    #[error("No transaction for BlockMetadata in fetched Block at height \"{height}\"")]
    /// In the block fetched through the API there is no block metadata transaction.
    BlockMetadataNotFound { height: String },
}
