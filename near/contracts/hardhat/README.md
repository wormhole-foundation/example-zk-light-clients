** Install

```shell
nvm install v18
yarn
npx hardhat help
```

** Unit tests

```shell
npx hardhat test

  Verifier
    ✔ should successfully execute the verifyProof request
    ✔ should successfully execute the verifyCompressedProof request
    ✔ should handle incorrect proof (53ms)
    NearBlockVerification
      ✔ should successfully execute the verifyAndSaveProof request
      ✔ should handle incorrect proof
      ✔ should successfully execute the verifyAndSaveCompressedProof request (50ms)
      ✔ should return false for isProofed when input is not proofed
      ✔ should return true for isProofed when input is proofed (38ms)
      ✔ should correctly convert array to hash
      ✔ should return false for isProofedHash when inputHash is not proofed
      ✔ should return true for isProofedHash when inputHash is proofed
      ✔ should set verifier correctly
      ✔ should emit ProofVerifiedAndSaved event
      ✔ should emit CompressedProofVerifiedAndSaved event (50ms)

  VerifierWith16Inputs
    ✔ should successfully execute the verifyProof request (61ms)
    ✔ should successfully execute the verifyCompressedProof request (98ms)
    NearBlockVerificationWith16Inputs
      ✔ should successfully execute the verifyAndSaveProof request
      ✔ should successfully execute the verifyAndSaveCompressedProof request (46ms)
      ✔ should return false for isProofed when input is not proofed
      ✔ should return true for isProofed when input is proofed (48ms)
      ✔ should correctly convert array to hash
      ✔ should return false for isProofedHash when inputHash is not proofed
      ✔ should return true for isProofedHash when inputHash is proofed (38ms)
      ✔ should set verifier correctly
    NearBlockVerificationWith16InputsIA
      ✔ should successfully execute the verifyAndSaveProof request
      ✔ should successfully execute the verifyAndSaveCompressedProof request (49ms)
      ✔ should return false for isProofed when input is not proofed
      ✔ should return true for isProofed when input is proofed (40ms)
      ✔ should correctly convert array to hash
      ✔ should return false for isProofedHash when inputHash is not proofed
      ✔ should return true for isProofedHash when inputHash is proofed
      ✔ should set verifier correctly


  32 passing (3s)

REPORT_GAS=true npx hardhat test

...

·------------------------------------------------------------------------|---------------------------|-------------|-----------------------------·
|                          Solc version: 0.8.20                          ·  Optimizer enabled: true  ·  Runs: 200  ·  Block limit: 30000000 gas  │
·········································································|···························|·············|······························
|  Methods                                                                                                                                       │
········································|································|·············|·············|·············|···············|··············
|  Contract                             ·  Method                        ·  Min        ·  Max        ·  Avg        ·  # calls      ·  usd (avg)  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  initialize                    ·          -  ·          -  ·      91635  ·           11  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  setVerifier                   ·          -  ·          -  ·      29021  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  verifyAndSaveCompressedProof  ·          -  ·          -  ·     278235  ·            3  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  verifyAndSaveProof            ·          -  ·          -  ·     269300  ·            5  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs    ·  setVerifier                   ·          -  ·          -  ·      28975  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs    ·  verifyAndSaveCompressedProof  ·          -  ·          -  ·     358914  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs    ·  verifyAndSaveProof            ·          -  ·          -  ·     350046  ·            3  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA  ·  setVerifier                   ·          -  ·          -  ·      28908  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA  ·  verifyAndSaveCompressedProof  ·          -  ·          -  ·     356619  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA  ·  verifyAndSaveProof            ·          -  ·          -  ·     347751  ·            3  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  Deployments                                                           ·                                         ·  % of limit   ·             │
·········································································|·············|·············|·············|···············|··············
|  NearBlockVerification                                                 ·          -  ·          -  ·     804076  ·        2.7 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs                                     ·          -  ·          -  ·     592883  ·          2 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA                                   ·     584256  ·     584268  ·     584267  ·        1.9 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  Verifier                                                              ·          -  ·          -  ·    1180829  ·        3.9 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  VerifierWith16Inputs                                                  ·          -  ·          -  ·    1535671  ·        5.1 %  ·          -  │
·------------------------------------------------------------------------|-------------|-------------|-------------|---------------|-------------·

  32 passing (3s)
```

** Deploy into goerli testnet

```shell
npx hardhat run --network goerli scripts/deploy_verifier.ts
Verifier deployed to: 0xe4a1B222D308896d09deFA29f89cAb596fBAbbDf

npx hardhat run --network goerli scripts/deploy_NearBlockVerification.ts
NearBlockVerification deployed to: 0x63F526335DB8458c76914BdBD88F0A97E1B6b157
```

** Deploy into sepolia testnet

```shell
npx hardhat run --network sepolia scripts/deploy_verifier.ts
Verifier deployed to: 0x20954439eB64259D2E62d4215d57Ef46086Bd87a

npx hardhat run --network sepolia scripts/deploy_NearBlockVerification.ts
NearBlockVerification deployed to: 0xce5845372e615Cbb46EFCc76c21051932BD8A717
```

** Tests in goerli testnet

```shell
export PROOF_PATH=test/proof_with_16_inputs_01.json && npx hardhat run --network goerli scripts/test_verifierWith16Inputs.ts
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/test_verifier.ts
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/test_NearBlockVerification.ts
```

** Tests in sepolia testnet

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network sepolia scripts/test_verifier.ts
Successfully completed!!

export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network sepolia scripts/test_NearBlockVerification.ts
nearBlockVerification.isProofed:  true
hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true
Successfully completed!!
```

** Verification in goerli testnet

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/verification.ts
hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true
```

** Verification in sepolia testnet

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network sepolia scripts/verification.ts
hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true
```

** Update Verifier contract in sepolia testnet

```shell
npx hardhat run --network sepolia scripts/update_verifier.ts
Verifier deployed to: 0x45b3d9C7810ab509c6fe0F394820dB49b2B36160
nearBlockVerification.getVerifier():  0x45b3d9C7810ab509c6fe0F394820dB49b2B36160
```

** Pause NearBlockVerification contract

```shell
npx hardhat run --network sepolia scripts/pause_NearBlockVerification.ts
nearBlockVerification.paused():  true
```

** Unpause NearBlockVerification contract

```shell
npx hardhat run --network sepolia scripts/unpause_NearBlockVerification.ts
nearBlockVerification.paused():  false
```
