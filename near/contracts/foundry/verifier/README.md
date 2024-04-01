## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Add OpenZeppelin lib

```shell
$ forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-commit
```

### Test

```shell
$ forge test

Ran 1 test for test/NearBlockVerification.t.sol:ConvertTest
[PASS] testToHash() (gas: 23561)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.26ms (209.60µs CPU time)

Ran 5 tests for test/NearBlockVerification.t.sol:OwnableTest
[PASS] testChangesOwnerAfterTransferOwnership() (gas: 18394)
[PASS] testGuardsOwnershipAgainstStuckState() (gas: 11233)
[PASS] testLosesOwnershipAfterRenouncement() (gas: 11192)
[PASS] testPreventsNonOwnersFromRenouncement() (gas: 13633)
[PASS] testPreventsNonOwnersFromTransferring() (gas: 13859)
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 1.84ms (602.04µs CPU time)

Ran 2 tests for test/NearBlockVerification.t.sol:SetupTest
[PASS] testRevertInitialize() (gas: 12955)
[PASS] testSetUp() (gas: 21417)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 914.45µs (245.57µs CPU time)

Ran 7 tests for test/NearBlockVerification.t.sol:PausableTest
[PASS] testCanNotVerifyInPause() (gas: 88087)
[PASS] testPause() (gas: 36196)
[PASS] testRevertPauseByNonOwner() (gas: 13614)
[PASS] testRevertPauseWhenAlreadyPaused() (gas: 35097)
[PASS] testRevertUnpauseByNonOwner() (gas: 37904)
[PASS] testRevertUnpauseWhenNotPaused() (gas: 30173)
[PASS] testUnpause() (gas: 26658)
Suite result: ok. 7 passed; 0 failed; 0 skipped; finished in 2.35ms (1.43ms CPU time)

Ran 1 test for test/NearBlockVerification.t.sol:SetVerifierTest
[PASS] testSetVerifier() (gas: 1098647)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 847.68µs (183.06µs CPU time)

Ran 5 tests for test/NearBlockVerification.t.sol:EventsTest
[PASS] testCompressedProofVerifiedAndSavedEvent() (gas: 312584)
[PASS] testInitializedEvent() (gas: 793868)
[PASS] testPausedEvent() (gas: 37382)
[PASS] testProofVerifiedAndSavedEvent() (gas: 283080)
[PASS] testUnpausedEvent() (gas: 27572)
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 20.69ms (20.13ms CPU time)

Ran 2 tests for test/NearBlockVerification.t.sol:ProofStatusTest
[PASS] testIsProofedHashWhenInputHashIsProofed() (gas: 280873)
[PASS] testIsProofedHashWhenInputHashNotProofed() (gas: 15318)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 23.31ms (22.41ms CPU time)

Ran 3 tests for test/Verifier.t.sol:VerifierTest
[PASS] testIncorrectProof() (gas: 8937393460516737801)
[PASS] testSuccessfulVerifyCompressedProof() (gas: 270197)
[PASS] testSuccessfulVerifyProof() (gas: 239681)
Suite result: ok. 3 passed; 0 failed; 0 skipped; finished in 24.22ms (35.10ms CPU time)

Ran 5 tests for test/NearBlockVerification.t.sol:VerifyTest
[PASS] testHandleIncorrectProof() (gas: 8797746687696168635)
[PASS] testIsProofedWhenInputIsNotProofed() (gas: 28580)
[PASS] testIsProofedWhenInputIsProofed() (gas: 280005)
[PASS] testSuccessfulVerifyAndSaveCompressedProof() (gas: 305882)
[PASS] testSuccessfulVerifyAndSaveProof() (gas: 274379)
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 24.42ms (40.72ms CPU time)

Ran 9 test suites in 31.73ms (99.85ms CPU time): 31 tests passed, 0 failed, 0 skipped (31 total tests)

```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy Verifier contract

```shell
Add to the .env file:
MAINNET_RPC_URL=<your_mainnet_rpc_url>
PRIVATE_KEY=<your_private_key>

$ source .env
$ forge script script/VerifierDeployment.s.sol:VerifierDeploymentScript --fork-url $MAINNET_RPC_URL --private-key $PRIVATE_KEY --broadcast

[⠒] Compiling...
No files changed, compilation skipped
Script ran successfully.

== Logs ==
  Verifier deployed to: 0xC7f2Cf4845C6db0e1a1e91ED41Bcd0FcC1b0E141
```

### Deploy NearBlockVerification contract

```shell
Add to the .env file:
MAINNET_RPC_URL=<your_mainnet_rpc_url>
PRIVATE_KEY=<your_private_key>
VERIFIER=<verifier_contract_address>

$ source .env
$ forge script script/NearBlockVerificationDeployment.s.sol:NearBlockVerificationDeploymentScript --fork-url $MAINNET_RPC_URL --private-key $PRIVATE_KEY --broadcast

[⠒] Compiling...
No files changed, compilation skipped
Script ran successfully.

== Logs ==
  NearBlockVerification deployed to: 0xC7f2Cf4845C6db0e1a1e91ED41Bcd0FcC1b0E141
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
