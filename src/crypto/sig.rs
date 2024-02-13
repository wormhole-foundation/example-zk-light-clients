// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use anyhow::format_err;
use blst::BLST_ERROR;
use getset::Getters;
use proptest::arbitrary::{any, Arbitrary};
use proptest::prelude::BoxedStrategy;
use proptest::strategy::Strategy;
use serde::Serialize;
use test_strategy::Arbitrary;

// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;

pub const DST_BLS_SIG_IN_G2_WITH_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Default, Debug, Clone, PartialEq, Eq, Copy)]
pub struct PublicKey {
    pub(crate) pubkey: blst::min_pk::PublicKey,
}

// for testing
impl Arbitrary for PublicKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let ikm = any::<[u8; 32]>();
        ikm.prop_map(|ikm| PublicKey {
            pubkey: blst::min_pk::SecretKey::key_gen_v3(&ikm[..], b"aptos test")
                .unwrap()
                .sk_to_pk(),
        })
        .boxed()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct(
            "PublicKey",
            serde_bytes::Bytes::new(self.pubkey.to_bytes().as_slice()),
        )
    }
}

impl PublicKey {
    /// Aggregates the public keys of several signers into an aggregate public key, which can be later
    /// used to verify a multisig aggregated from those signers.
    ///
    /// WARNING: This function assumes all public keys have had their proofs-of-possession verified
    /// and have thus been group-checked.
    pub fn aggregate(pubkeys: Vec<&Self>) -> anyhow::Result<PublicKey> {
        let blst_pubkeys: Vec<_> = pubkeys.iter().map(|pk| &pk.pubkey).collect();

        // CRYPTONOTE(Alin): We assume the PKs have had their PoPs verified and thus have also been subgroup-checked
        let aggpk = blst::min_pk::AggregatePublicKey::aggregate(&blst_pubkeys[..], false)
            .map_err(|e| format_err!("{:?}", e))?;

        Ok(PublicKey {
            pubkey: aggpk.to_public_key(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) sig: blst::min_pk::Signature,
}

impl Signature {
    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> anyhow::Result<()> {
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

#[derive(Debug, PartialEq, Eq, Arbitrary)]
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

impl Arbitrary for Signature {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let ikm = any::<[u8; 32]>();
        ikm.prop_map(|ikm| {
            let sk = blst::min_pk::SecretKey::key_gen_v3(&ikm[..], b"aptos test").unwrap();
            let sig = sk.sign(b"test msg", DST_BLS_SIG_IN_G2_WITH_POP, &[]);
            Signature { sig }
        })
        .boxed()
    }
}

#[derive(Debug, PartialEq, Eq, Getters, Arbitrary)]
pub struct AggregateSignature {
    validator_bitmask: BitVec,
    #[getset(get = "pub")]
    sig: Option<Signature>,
}

impl AggregateSignature {
    pub fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }
}
