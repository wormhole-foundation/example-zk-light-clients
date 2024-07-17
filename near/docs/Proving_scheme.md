Proving scheme
==============

The scheme implements an algorithm to prove computational integrity of randomly selected Near blocks. In addition, an important point is to ensure full block finality of the chosen block. 

*The implementation is based on the [Plonky2](https://github.com/0xPolygonZero/plonky2/tree/main) framework developed by Polygon Zero, [ed25519](https://github.com/polymerdao/plonky2-ed25519) scheme developed by PolymerDAO and [SHA-256](https://github.com/JumpCrypto/plonky2-crypto/tree/main/src) implemented by Jump Crypto.*

The scheme relies on the following explanation of full finality: *"… if a block produced by Doomslug contains endorsements on the previous block from more than half of the block producers, the previous block is irreversible unless at least one of the block producers is slashed. … there’s a finality gadget that operates together with Doomslug. Under normal circumstances once a block at height `h+1` is produced, and the block at height `h` has doomslug finality, the block at height `h-1` will have a full BFT finality. In other words, at least ⅓ of the total stake would need to be slashed to revert it."* [Source](https://near.org/blog/doomslug-comparison)

Near block headers have the following structure:

![Near block header](/near/schemes/1_Near_block_header.png)
*Fig. 1 – Near block header*

where:
- `last_ds_final_block` is the hash of the last block that has doomslug finality, i.e. hash of the block *i-1*;
- `last_final_block` is the hash of the last block that has full BFT finality, i.e. hash of the block *i-2*;
- `approvals` of the block *i* are signatures to block *i-1*;
- `next_bp_hash` is the hash of the next epoch block producers set;
- `epoch_id` is the ID of the current epoch. It matches the hash of the last block of the epoch *i-2*.

The idea is to prove the full block finality (BFT finality) by proving the Doomslug finality. In this case, we need at least three blocks: `Block_i` (that needs to be proved, BFT finality), `Block_i+1` (Doomslug finality), `Block_i+2`. But we take five blocks instead to ensure block full finality: `Block_i` (that needs to be proved, BFT finality), `Block_i+1` (BFT finality), `Block_i+2` (BFT finality), `Block_i+3` (Doomslug finality), `Block_i+4`.

Additionally, we take two more blocks: 
- `Block_n-1`, i.e. the last block of the epoch *i-2*, to prove `epoch_id`;
- `Block_0`, i.e. the first block of the epoch *i-1*, to prove the correspondence of the used list of validators for the current epoch with the field `next_bp_hash` if the `Block_0`. 

Unlike `Block_i`, `Block_i+1`, etc., whose block body and hash are loaded from RCP, the block bodies of `Block_n-1` and `Block_0` are loaded from RPC, and their hashes are stored in the smart-contract to ensure the validity of the provided hash.

![Used data in proving scheme](/near/schemes/2_Used_data_in_proving_scheme.png)
*Fig. 2 – Used data in proving scheme*

We make two chains: the first one represents proofs for "epoch blocks" and the second one for "ordinary blocks". 

"Epoch blocks" represent the first block from epoch *i* and the last block from epoch *i-1*. This case validates hashes for "trusted points", that are stored in smart-contract and could be further used while proving `epoch_id` & `next_bp_hash` fields. Since these blocks are also loaded from RCP, their BFT finality also needs to be proven. In this case, proving algorithm takes `Block_n-1`,  `Block_0`, `Block_1`, `Block_2`, `Block_3`, `Block_4`, `Block_n-1` (epoch *i-2*) and `Block_0` (epoch *i-1*) as input to prove computational integrity and BFT finality of blocks `Block_n-1`, `Block_0` and store their hashes in smart-contract.

"Ordinary blocks" represent a randomly selected Block_i and four more blocks to ensure BFT finality of the chosen block. The proving algorithm takes `Block_i`, `Block_i+1`, `Block_i+2`, `Block_i+3`, `Block_i+4` and `Block_n-1` & `Block_0` and their hashes from smart-contract as input to prove computational integrity of `Block_i`.

To make the system work we set the four hashes as valid in smart-contract without proving them: `Block_n-1` (epoch *0*), `Block_0` & `Block_n-1` (epoch *1*), `Block_0` (epoch *2*). These hashes are so-called “genesis hashes”, we assume them to be trusted by all participants in the network. This makes it possible to prove randomly selected blocks starting from epoch *2* and prove "epoch blocks" starting from epochs *⅔*, i.e. `Block_n-1` (epoch *2*) and `Block_0` (epoch *3*).

*Proof_Block_n-1_Epoch_i-2.* We prove the hash of the block using block data from rpc & hash from smart-contract to ensure the validity of the hash provided. We set the hash as public inputs (PI) to prove later the correspondence of the hash and the `epoch_id` field. 

The output is `Proof_Block_n-1_Epoch_i-2` with the `hash` of this block as its PI. 

*Proof_Block_0_Epoch_i-1.* We prove the hash of the previous epoch block using block data from rpc & hash from smart-contract to ensure the validity of the hash provided. We set `hash` & `next_bp_hash` as public inputs (PI) to prove later the correspondence of the hashed list of validators to the hash in the field `next_bp_hash`. 

The output is `Proof_Block_0_Epoch_i-1` with the `hash` of this block & `next_bp_hash` as its PI. 

*Proof_Block_i+4 (Epoch_i).* To prove that the block `Block_i+4` exists we just prove its hash with SHA256 and set its `hash`, `last_ds_final_block` & `last_final_block` as public inputs. 

The output is `Proof_Block_i+4` with the `hash`, `last_ds_final_block` & `last_final_block` as its PI. 

*Proof_Block_i+3 (Epoch_i).* To prove doomslug finality of the block `Block_i+3` we follow the next steps:
- Prove the hash of the block `Block_i+3` with SHA256.
- Prove all signatures of the block `Block_i+3`, i.e. its endorsements, that are stored in block `Block_i+4` with ED25519.
- Prove valid keys (existence of valid keys filtered while proving signatures) & stakes (the sum of stakes that correspond to “valid keys” >=2/3 of the sum of all stakes in the list of validators).
- Verification of `Proof_Block_0_Epoch_i-1`.
- Prove bp hash, i.e. the correspondence of hashed list of validators to the hash in the field `next_bp_hash` in the previous epoch block that is extracted from PI of `Proof_Block_0_Epoch_i-1` (SHA256).
- Verification of `Proof_Block_i+4`.
- Proof of the correspondence (that arrays of data are equal) of the `hash` of the block `Block_i+3` and the field  `last_ds_final_block` that we extract from PI of `Proof_Block_i+4`.
- Verification of `Proof_Block_n-1_Epoch_i-2`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of the `Block_n-1` extracted from PI of `Proof_Block_n-1_Epoch_i-2` with `epoch_id` of this block.

The output is `Proof_Block_i+3` with the `hash`, `prev_hash`, `last_ds_final_block` & `last_final_block` as its PI. 

*Proof_Block_i+2 (Epoch_i).* To prove BFT finality of the block `Block_i+2` we follow the next steps:
- Prove the hash of the block `Block_i+2` with SHA256.
- Verification of `Proof_Block_i+3`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of this block and `prev_hash` field extracted from PI of `Proof_Block_i+3`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of this block and `last_ds_final_block` field extracted from PI of `Proof_Block_i+3`.
- Verification of `Proof_Block_i+4`.
- Proof of the correspondence (that arrays of data are equal) of the `hash` of this block and the field `last_final_block` extracted from PI of `Proof_Block_i+4`.
- Verification of `Proof_Block_0_Epoch_i+1`.
- Verification of `Proof_Block_n-1_Epoch_i-2`.
- Proof the correspondence (that arrays of data are equal) of the hash of the `Block_n-1` extracted from PI of `Proof_Block_n-1_Epoch_i-2` with `epoch_id` of this block.

The output is `Proof_Block_i+2` with the `hash`, `prev_hash`, `last_ds_final_block` & `last_final_block` as its PI. 

*Proof_Block_i+1 (Epoch_i).* To prove BFT finality of the block `Block_i+1` we follow the next steps:
- Prove the hash of the block `Block_i+1` with SHA256.
- Verification of `Proof_Block_i+2`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of this block and `prev_hash` field extracted from PI of `Proof_Block_i+2`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of this block and `last_ds_final_block` field extracted from PI of `Proof_Block_i+2`.
- Verification of `Proof_Block_i+3`.
- Proof of the correspondence (that arrays of data are equal) of the `hash` of this block and the field `last_final_block` extracted from PI of `Proof_Block_i+3`.
- Verification of `Proof_Block_0_Epoch_i+1`.
- Verification of `Proof_Block_n-1_Epoch_i-2`.
- Proof the correspondence (that arrays of data are equal)  of the hash of the `Block_n-1` extracted from PI of `Proof_Block_n-1_Epoch_i-2` with `epoch_id` of this block.
- Verification of `Proof_Block_i+4`.

The output is `Proof_Block_i+1` with the `hash`, `prev_hash`, `last_ds_final_block` as its PI. 

*Proof_Block_i (Epoch_i).* To prove BFT finality of the block `Block_i` we follow the next steps:
- Prove the hash of the block `Block_i` with SHA256.
- Verification of `Proof_Block_i+1`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of this block and `prev_hash` field extracted from PI of `Proof_Block_i+1`.
- Proof the correspondence (that arrays of data are equal) of the `hash` of this block and `last_ds_final_block` field extracted from PI of `Proof_Block_i+1`.
- Verification of `Proof_Block_i+2`.
- Proof of the correspondence (that arrays of data are equal) of the `hash` of this block and the field `last_final_block` extracted from PI of `Proof_Block_i+2`.
- Verification of `Proof_Block_0_Epoch_i+1`.
- Verification of `Proof_Block_n-1_Epoch_i-2`.
- Proof the correspondence (that arrays of data are equal) of the hash of the `Block_n-1` extracted from PI of `Proof_Block_n-1_Epoch_i-2` with `epoch_id` of this block.
- Verification of `Proof_Block_i+3`.
- Verification of `Proof_Block_i+4`.

The output is `Proof_Block_i` with the `hash` as its PI. 


![Proofs for "epoch blocks"](/near/schemes/3_Proofs_for_epoch_blocks.png)
*Fig. 3 — Proofs for "epoch blocks"*


![Proof of Doomslug/BFT finality](/near/schemes/4_Proof_of_Doomslug_BFT_finality.png)
*Fig. 4 — Proof of Doomslug/BFT finality*


Proving block header hash
============

The scheme of proving hash of the block implements [SHA256](https://en.wikipedia.org/wiki/SHA-2). Its input data is a message and a digest, the validity of which has to be verified. The scheme generates a digest based on a provided message and compares it to the given one. A digest is set to public inputs of a proof. There are some other fiels like `prev_hash`, `last_ds_final_block` etc. that could be set to public inputs.

![Scheme of proving block header hash](/near/schemes/5_Scheme_of_proving_block_header_hash.png)
*Fig. 5 – Scheme of proving block header hash*

Proving signatures
==================

The scheme of proving hash implements [EdDSA](https://en.wikipedia.org/wiki/EdDSA) over the 255-bit curve [Curve25519](https://en.wikipedia.org/wiki/Curve25519). It takes a message, signatures and public keys as input. A message is chosen for each block by the following rule: if the next block exists, the validators sign a hash of the previous block with the height of the current one, otherwise a missed height with the height of the current block. Public keys are provided from the validators list. Signatures are provided from the next block.

The scheme generates proofs for each signature separately and aggregates them later one by one. Since the proving process is made for one message for the whole block, we generate the circuit once and then reuse it for all signatures to make different proofs.

This step also filters all keys and creates a list of valid keys, for which there are verified signatures. This list is hashed and its digest is set to public inputs of the resulting proof. This is done to ensure that the list of filtered keys is valid while proving its existence in the whole validators list in the next step.

![Scheme of proving signatures](/near/schemes/6_Scheme_of_proving_signatures.png)
*Fig. 6 – Scheme of proving signatures*

Proving keys & ⅔ stakes
=======================

This scheme proves the existence of filtered keys on the previous step in the validators list, computes a sum of stakes for these valid keys and checks whether this sum is >= ⅔ of the sum of all stakes of the validator list. Since a list of valid keys is provided as a vector and cannot be considered as trusted data we also check its hash with the one which is stored in the proof of aggregated signatures (which is considered to be valid). This step generates proof for keys & stakes and proof for hash of list of keys. Then the scheme aggregates them into one and sets a list of keys and a sum of stakes as public inputs.

![Scheme of proving keys & stakes](/near/schemes/7_Scheme_of_proving_keys_stakes.png)
*Fig. 7 – Scheme of proving keys & stakes*

Proving hash of the next epoch block producers set
====================

The scheme of proving hash of the next epoch block producers set implements SHA-256 and checks if a hash of the list of validators matches the field `next_bp_hash`, that is stores in public inputs of a proof of the previous epoch block. The public inputs of this proof is a verified `next_bp_hash`.