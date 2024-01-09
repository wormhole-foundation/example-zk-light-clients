//! structs reproduced identically with BCS derived ser/de
//!
use std::{ops::Deref, collections::HashMap};

// for ser/de
// https://github.com/aptos-labs/bcs/commit/d31fab9d81748e2594be5cd5cdf845786a30562d
//
use anyhow::{bail, ensure, format_err, Result};
use blst::BLST_ERROR;
use getset::{CopyGetters, Getters};
use serde::{Serialize, Serializer};
use thiserror::Error;
use tiny_keccak::Hasher;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
pub struct HashValue {
    hash: [u8; 32],
}

pub type Round = u64;
pub type Version = u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EpochState {
    pub epoch: u64,
    pub verifier: ValidatorVerifier,
}

impl EpochState {
    fn epoch_change_verification_required(&self, epoch: u64) -> bool {
        self.epoch < epoch
    }

    fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        ledger_info.epoch() < self.epoch
    }

    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct AccountAddress([u8; 16]);

impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // See comment in deserialize.
        serializer.serialize_newtype_struct("AccountAddress", &self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct PublicKey {
    pub(crate) pubkey: blst::min_pk::PublicKey,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_newtype_struct(
            "PublicKey",
            serde_bytes::Bytes::new(&self.pubkey.to_bytes().as_slice()),
        )
    }
}

impl PublicKey {
    /// Aggregates the public keys of several signers into an aggregate public key, which can be later
    /// used to verify a multisig aggregated from those signers.
    ///
    /// WARNING: This function assumes all public keys have had their proofs-of-possession verified
    /// and have thus been group-checked.
    pub fn aggregate(pubkeys: Vec<&Self>) -> Result<PublicKey> {
        let blst_pubkeys: Vec<_> = pubkeys.iter().map(|pk| &pk.pubkey).collect();

        // CRYPTONOTE(Alin): We assume the PKs have had their PoPs verified and thus have also been subgroup-checked
        let aggpk = blst::min_pk::AggregatePublicKey::aggregate(&blst_pubkeys[..], false)
            .map_err(|e| format_err!("{:?}", e))?;

        Ok(PublicKey {
            pubkey: aggpk.to_public_key(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, CopyGetters, Serialize)]
pub struct ValidatorConsensusInfo {
    #[getset(get_copy)]
    address: AccountAddress,
    #[getset(get_copy)]
    public_key: PublicKey, // bls12-381
    voting_power: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)] // this derive is in the original code, but it's probably a bug, as Validator set comparisons should have set (not list) semantics
pub struct ValidatorVerifier {
    /// A vector of each validator's on-chain account address to its pubkeys and voting power.
    validator_infos: Vec<ValidatorConsensusInfo>,
    // Recomputed on deserialization:
    // // The minimum voting power required to achieve a quorum
    // #[serde(skip)]
    // quorum_voting_power: u128,
    // // Total voting power of all validators (cached from address_to_validator_info)
    // #[serde(skip)]
    // total_voting_power: u128,
    // // In-memory index of account address to its index in the vector, does not go through serde.
    // #[serde(skip)]
    // address_to_validator_index: HashMap<AccountAddress, usize>,
}

impl ValidatorVerifier {
    /// Returns the number of authors to be validated.
    pub fn len(&self) -> usize {
        self.validator_infos.len()
    }    


    /// Ensure there are not more than the maximum expected voters (all possible signatures).
    fn check_num_of_voters(
        num_validators: u16,
        bitvec: &BitVec,
    ) -> std::result::Result<(), VerifyError> {
        if bitvec.num_buckets() != BitVec::required_buckets(num_validators) {
            return Err(VerifyError::InvalidBitVec);
        }
        if let Some(last_bit) = bitvec.last_set_bit() {
            if last_bit >= num_validators {
                return Err(VerifyError::InvalidBitVec);
            }
        }
        Ok(())
    }


    /// Returns sum of voting power from Map of validator account addresses, validator consensus info
    fn s_voting_power(address_to_validator_info: &[ValidatorConsensusInfo]) -> u128 {
        address_to_validator_info.iter().fold(0, |sum, x| {
            sum.checked_add(x.voting_power as u128)
                .expect("sum of all voting power is greater than u64::max")
        })
    }

    // TODO: Make this more efficient
    pub fn total_voting_power(&self) -> u128 {
        Self::s_voting_power(&self.validator_infos[..])
    }

    
    pub fn quorum_voting_power(&self) -> u128 {
        if self.validator_infos.is_empty() {
                0
            } else {
                self.total_voting_power() * 2 / 3 + 1
            }
        }

    /// Returns the voting power for this address.
    pub fn get_voting_power(&self, author: &AccountAddress) -> Option<u64> {
        // TODO : make this more efficient
        let address_to_validator_index = self.validator_infos
            .iter()
            .enumerate()
            .map(|(index, info)| (info.address, index))
            .collect::<HashMap<_, _>>();

        address_to_validator_index
            .get(author)
            .map(|index| self.validator_infos[*index].voting_power)
    }

    /// Sum voting power for valid accounts, exiting early for unknown authors
    pub fn sum_voting_power<'a>(
        &self,
        authors: impl Iterator<Item = &'a AccountAddress>,
    ) -> std::result::Result<u128, VerifyError> {
        let mut aggregated_voting_power = 0;
        for account_address in authors {
            match self.get_voting_power(account_address) {
                Some(voting_power) => aggregated_voting_power += voting_power as u128,
                None => return Err(VerifyError::UnknownAuthor),
            }
        }
        Ok(aggregated_voting_power)
    }

    /// Ensure there is at least quorum_voting_power in the provided signatures and there
    /// are only known authors. According to the threshold verification policy,
    /// invalid public keys are not allowed.
    pub fn check_voting_power<'a>(
        &self,
        authors: impl Iterator<Item = &'a AccountAddress>,
        check_super_majority: bool,
    ) -> std::result::Result<u128, VerifyError> {
        let aggregated_voting_power = self.sum_voting_power(authors)?;

        let target = if check_super_majority {
            self.quorum_voting_power()
        } else {
            self.total_voting_power() - self.quorum_voting_power() + 1
        };

        if aggregated_voting_power < target {
            return Err(VerifyError::TooLittleVotingPower {
                voting_power: aggregated_voting_power,
                expected_voting_power: target,
            });
        }
        Ok(aggregated_voting_power)
    }

    const HASH_PREFIX: &'static [u8] = b"APTOS::";

    fn prefixed_sha3(input: &[u8]) -> [u8; 32] {
        let mut sha3 = ::tiny_keccak::Sha3::v256();
        let salt: Vec<u8> = [Self::HASH_PREFIX, input].concat();
        sha3.update(&salt);
        let mut output = [0u8; 32];
        sha3.finalize(&mut output);
        output
    }

    pub fn verify_multi_signatures(
        &self,
        message: &LedgerInfo,
        multi_signature: &AggregateSignature,
    ) -> std::result::Result<(), VerifyError> {
        // Verify the number of signature is not greater than expected.
        Self::check_num_of_voters(self.len() as u16, multi_signature.get_signers_bitvec())?;
        let mut pub_keys = vec![];
        let mut authors = vec![];
        for index in multi_signature.get_signers_bitvec().iter_ones() {
            let validator = self
                .validator_infos
                .get(index)
                .ok_or(VerifyError::UnknownAuthor)?;
            authors.push(validator.address());
            pub_keys.push(validator.public_key());
        }
        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.iter(), true)?;
        #[cfg(any(test, feature = "fuzzing"))]
        {
            if self.quorum_voting_power() == 0 {
                // This should happen only in case of tests.
                // TODO(skedia): Clean up the test behaviors to not rely on empty signature
                // verification
                return Ok(());
            }
        }
        // Verify empty multi signature
        let multi_sig = multi_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;
        let pk_refs = pub_keys.iter().collect::<Vec<&PublicKey>>();
        // Verify the optimistically aggregated signature.
        let aggregated_key =
            PublicKey::aggregate(pk_refs).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

        // see aptos_crypto::unit_tests::cryptohasher
        let mut bytes = Self::prefixed_sha3(b"LedgerInfo").to_vec();
        bcs::serialize_into(&mut bytes, &message)
             .map_err(|_| VerifyError::InvalidMultiSignature)?;

        multi_sig
            .verify(&bytes, &aggregated_key)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, CopyGetters, Getters, Serialize)]
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    #[getset(get_copy)]
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    #[getset(get_copy)]
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    #[getset(get_copy)]
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    #[getset(get_copy)]
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    #[getset(get)]
    next_epoch_state: Option<EpochState>,
}

impl BlockInfo {
    /// The epoch after this block committed
    pub fn next_block_epoch(&self) -> u64 {
        self.next_epoch_state().as_ref().map_or(self.epoch(), |e| e.epoch)
    }
}

/// Errors possible during signature verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("Author is unknown")]
    /// The author for this signature is unknown by this validator.
    UnknownAuthor,
    #[error(
        "The voting power ({}) is less than expected voting power ({})",
        voting_power,
        expected_voting_power
    )]
    TooLittleVotingPower {
        voting_power: u128,
        expected_voting_power: u128,
    },
    #[error("Signature is empty")]
    /// The signature is empty
    EmptySignature,
    #[error("Multi signature is invalid")]
    /// The multi signature is invalid
    InvalidMultiSignature,
    #[error("Aggregated signature is invalid")]
    /// The multi signature is invalid
    InvalidAggregatedSignature,
    #[error("Inconsistent Block Info")]
    InconsistentBlockInfo,
    #[error("Failed to aggregate public keys")]
    FailedToAggregatePubKey,
    #[error("Failed to aggregate signatures")]
    FailedToAggregateSignature,
    #[error("Failed to verify multi-signature")]
    FailedToVerifyMultiSignature,
    #[error("Invalid bitvec from the multi-signature")]
    InvalidBitVec,
    #[error("Failed to verify aggreagated signature")]
    FailedToVerifyAggregatedSignature,
}

// NOTE:
// use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
// #[derive(BCSCryptoHash, CryptoHasher)]
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct LedgerInfo {
    commit_info: BlockInfo,
    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl LedgerInfo {
    pub fn epoch(&self) -> u64 {
        self.commit_info.epoch()
    }

    pub fn next_block_epoch(&self) -> u64 {
        self.commit_info.next_block_epoch()
    }

    pub fn next_epoch_state(&self) -> Option<&EpochState> {
        self.commit_info.next_epoch_state().as_ref()
    }

    pub fn timestamp_usecs(&self) -> u64 {
        self.commit_info.timestamp_usecs()
    }

    pub fn transaction_accumulator_hash(&self) -> HashValue {
        self.commit_info.executed_state_id()
    }

    pub fn version(&self) -> Version {
        self.commit_info.version()
    }
}

pub const DST_BLS_SIG_IN_G2_WITH_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) sig: blst::min_pk::Signature,
}

impl Signature {
    fn verify(&self, message: &[u8], public_key: &PublicKey) -> Result<()> {
        let result = self.sig.verify(
            true,
            message,
            DST_BLS_SIG_IN_G2_WITH_POP,
            &[],
            &public_key.pubkey,
            false,
        );
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(format_err!("{:?}", result))
        }
    }
}

// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct BitVec {
    inner: Vec<u8>,
}

impl BitVec {
    /// Number of buckets require for num_bits.
    pub fn required_buckets(num_bits: u16) -> usize {
        num_bits
            .checked_sub(1)
            .map_or(0, |pos| pos as usize / BUCKET_SIZE + 1)
    }

    /// Checks if the bit at position @pos is set.
    #[inline]
    pub fn is_set(&self, pos: u16) -> bool {
        // This is optimised to: let bucket = pos >> 3;
        let bucket: usize = pos as usize / BUCKET_SIZE;
        if self.inner.len() <= bucket {
            return false;
        }
        // This is optimized to: let bucket_pos = pos | 0x07;
        let bucket_pos = pos as usize - (bucket * BUCKET_SIZE);
        (self.inner[bucket] & (0b1000_0000 >> bucket_pos as u8)) != 0
    }

    /// Return the number of buckets.
    pub fn num_buckets(&self) -> usize {
        self.inner.len()
    }

    /// Return an `Iterator` over all '1' bit indexes.
    pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.inner.len() * BUCKET_SIZE).filter(move |idx| self.is_set(*idx as u16))
    }

    /// Returns the index of the last set bit.
    pub fn last_set_bit(&self) -> Option<u16> {
        self.inner
            .iter()
            .rev()
            .enumerate()
            .find(|(_, byte)| byte != &&0u8)
            .map(|(i, byte)| {
                (8 * (self.inner.len() - i) - byte.trailing_zeros() as usize - 1) as u16
            })
    }
}

#[derive(Debug, PartialEq, Eq, Getters)]
pub struct AggregateSignature {
    validator_bitmask: BitVec,
    #[getset(get)]
    sig: Option<Signature>,
}

impl AggregateSignature {
    pub fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }
}

#[derive(Debug, Getters, PartialEq, Eq)]
pub struct LedgerInfoWithV0 {
    #[getset(get)]
    ledger_info: LedgerInfo,
    /// Aggregated BLS signature of all the validators that signed the message. The bitmask in the
    /// aggregated signature can be used to find out the individual validators signing the message
    signatures: AggregateSignature,
}

impl LedgerInfoWithV0 {
    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerInfoWithSignatures {
    V0(LedgerInfoWithV0),
}

// This deref polymorphism anti-pattern is in the upstream code (!)
impl Deref for LedgerInfoWithSignatures {
    type Target = LedgerInfoWithV0;

    fn deref(&self) -> &LedgerInfoWithV0 {
        match &self {
            LedgerInfoWithSignatures::V0(ledger) => ledger,
        }
    }
}

// #[derive(CryptoHasher, BCSCryptoHash)]
// This is just made to hash the LedgerInfo
#[allow(dead_code)] // remove this when implementing hash()
struct Ledger2WaypointConverter {
    epoch: u64,
    root_hash: HashValue,
    version: Version,
    timestamp_usecs: u64,
    next_epoch_state: Option<EpochState>,
}

impl Ledger2WaypointConverter {
    pub fn new(ledger_info: &LedgerInfo) -> Self {
        Self {
            epoch: ledger_info.epoch(),
            root_hash: ledger_info.transaction_accumulator_hash(),
            version: ledger_info.version(),
            timestamp_usecs: ledger_info.timestamp_usecs(),
            next_epoch_state: ledger_info.next_epoch_state().cloned(),
        }
    }

    pub fn hash(&self) -> HashValue {
        todo!("emulate BCS CryptoHasher")
    }
}

#[derive(Debug, CopyGetters, PartialEq, Eq, Clone, Copy)]
pub struct Waypoint {
    /// The version of the reconfiguration transaction that is being approved by this waypoint.
    #[getset(get_copy)]
    version: Version,
    /// The hash of the chosen fields of LedgerInfo.
    value: HashValue,
}

impl Waypoint {
    /// Generate a new waypoint given any LedgerInfo.
    pub fn new_any(ledger_info: &LedgerInfo) -> Self {
        let converter = Ledger2WaypointConverter::new(ledger_info);
        Self {
            version: ledger_info.version(),
            value: converter.hash(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TrustedState {
    /// The current trusted state is an epoch waypoint, which is a commitment to
    /// an epoch change ledger info. Most light clients will start here when
    /// syncing for the first time.
    EpochWaypoint(Waypoint),
    /// The current trusted state is inside a verified epoch (which includes the
    /// validator set inside that epoch).
    EpochState {
        /// The current trusted version and a commitment to a ledger info inside
        /// the current trusted epoch.
        waypoint: Waypoint,
        /// The current epoch and validator set inside that epoch.
        epoch_state: EpochState,
    },
}

#[derive(Debug)]
pub enum TrustedStateChange<'a> {
    /// We have a newer `TrustedState` but it's still in the same epoch, so only
    /// the latest trusted version changed.
    Version { new_state: TrustedState },
    /// We have a newer `TrustedState` and there was at least one epoch change,
    /// so we have a newer trusted version and a newer trusted validator set.
    Epoch {
        new_state: TrustedState,
        latest_epoch_change_li: &'a LedgerInfoWithSignatures,
    },
    /// The latest ledger info is at the same version as the trusted state and matches the hash.
    NoChange,
}

/// A vector of LedgerInfo with contiguous increasing epoch numbers to prove a sequence of
/// epoch changes from the first LedgerInfo's epoch.
pub struct EpochChangeProof {
    pub ledger_info_with_sigs: Vec<LedgerInfoWithSignatures>,
    pub more: bool,
}

impl EpochChangeProof {
    /// Verify the proof is correctly chained with known epoch and validator
    /// verifier and return the [`LedgerInfoWithSignatures`] to start target epoch.
    ///
    /// In case a waypoint is present, it's going to be used for verifying the
    /// very first epoch change (it's the responsibility of the caller to not
    /// pass a waypoint in case it's not needed).
    ///
    /// We will also skip any stale ledger info's in the [`EpochChangeProof`].
    pub fn verify(&self, verifier: &TrustedState) -> Result<&LedgerInfoWithSignatures> {
        ensure!(
            !self.ledger_info_with_sigs.is_empty(),
            "The EpochChangeProof is empty"
        );
        ensure!(
            !verifier
                .is_ledger_info_stale(self.ledger_info_with_sigs.last().unwrap().ledger_info()),
            "The EpochChangeProof is stale as our verifier is already ahead \
             of the entire EpochChangeProof"
        );
        let mut trusted_state: TrustedState = verifier.clone();

        for ledger_info_with_sigs in self
            .ledger_info_with_sigs
            .iter()
            // Skip any stale ledger infos in the proof prefix. Note that with
            // the assertion above, we are guaranteed there is at least one
            // non-stale ledger info in the proof.
            //
            // It's useful to skip these stale ledger infos to better allow for
            // concurrent client requests.
            //
            // For example, suppose the following:
            //
            // 1. My current trusted state is at epoch 5.
            // 2. I make two concurrent requests to two validators A and B, who
            //    live at epochs 9 and 11 respectively.
            //
            // If A's response returns first, I will ratchet my trusted state
            // to epoch 9. When B's response returns, I will still be able to
            // ratchet forward to 11 even though B's EpochChangeProof
            // includes a bunch of stale ledger infos (for epochs 5, 6, 7, 8).
            //
            // Of course, if B's response returns first, we will reject A's
            // response as it's completely stale.
            .skip_while(|&ledger_info_with_sigs| {
                verifier.is_ledger_info_stale(ledger_info_with_sigs.ledger_info())
            })
        {
            // Try to verify each (epoch -> epoch + 1) jump in the EpochChangeProof.
            trusted_state.verify(ledger_info_with_sigs)?;
            // While the original verification could've been via waypoints,
            // all the next epoch changes are verified using the (already
            // trusted) validator sets.
            let new_li = ledger_info_with_sigs.ledger_info();

            let new_epoch_state = new_li
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
            let new_waypoint = Waypoint::new_any(new_li);
            let new_trusted_state = TrustedState::EpochState {
                waypoint: new_waypoint,
                epoch_state: new_epoch_state.clone(),
            };
            trusted_state = new_trusted_state;
        }

        Ok(self.ledger_info_with_sigs.last().unwrap())
    }
}

impl TrustedState {
    pub fn version(&self) -> Version {
        self.waypoint().version()
    }

    pub fn waypoint(&self) -> Waypoint {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { waypoint, .. } => *waypoint,
        }
    }

    fn epoch_change_verification_required(&self, epoch: u64) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => {
                epoch_state.epoch_change_verification_required(epoch)
            }
        }
    }

    fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.is_ledger_info_stale(ledger_info),
        }
    }

    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.verify(ledger_info),
        }
    }

    /// The main LC method
    pub fn verify_and_ratchet_inner<'a>(
        &self,
        latest_li: &'a LedgerInfoWithSignatures,
        epoch_change_proof: &'a EpochChangeProof,
    ) -> Result<TrustedStateChange<'a>> {
        // Abort early if the response is stale.
        let curr_version = self.version();
        let target_version = latest_li.ledger_info().version();
        ensure!(
            target_version >= curr_version,
            "The target latest ledger info version is stale ({}) and behind our current trusted version ({})",
            target_version, curr_version,
        );

        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
            let new_epoch_state = epoch_change_li
                .ledger_info()
                .next_epoch_state()
                .cloned()
                .ok_or_else(|| {
                    format_err!(
                        "A valid EpochChangeProof will never return a non-epoch change ledger info"
                    )
                })?;

            // If the latest ledger info is in the same epoch as the new verifier, verify it and
            // use it as latest state, otherwise fallback to the epoch change ledger info.
            let new_epoch = new_epoch_state.epoch;

            let verified_ledger_info = if epoch_change_li == latest_li {
                latest_li
            } else if latest_li.ledger_info().epoch() == new_epoch {
                new_epoch_state.verify(latest_li)?;
                latest_li
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };
            let new_waypoint = Waypoint::new_any(verified_ledger_info.ledger_info());

            let new_state = TrustedState::EpochState {
                waypoint: new_waypoint,
                epoch_state: new_epoch_state,
            };

            Ok(TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li: epoch_change_li,
            })
        } else {
            let (curr_waypoint, curr_epoch_state) = match self {
                Self::EpochWaypoint(_) => {
                    bail!("EpochWaypoint can only verify an epoch change ledger info")
                }
                Self::EpochState {
                    waypoint,
                    epoch_state,
                    ..
                } => (waypoint, epoch_state),
            };

            // The EpochChangeProof is empty, stale, or only gets us into our
            // current epoch. We then try to verify that the latest ledger info
            // is inside this epoch.
            let new_waypoint = Waypoint::new_any(latest_li.ledger_info());
            if new_waypoint.version() == curr_waypoint.version() {
                ensure!(
                    &new_waypoint == curr_waypoint,
                    "LedgerInfo doesn't match verified state"
                );
                Ok(TrustedStateChange::NoChange)
            } else {
                // Verify the target ledger info, which should be inside the current epoch.
                curr_epoch_state.verify(latest_li)?;

                let new_state = Self::EpochState {
                    waypoint: new_waypoint,
                    epoch_state: curr_epoch_state.clone(),
                };

                Ok(TrustedStateChange::Version { new_state })
            }
        }
    }
}
