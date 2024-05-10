import Web3 from 'web3';

const web3 = new Web3(process.env.SEPOLIA_RPC || 'https://rpc2.sepolia.org');

const contractAddress =
  process.env.NEAR_BLOCK_VERIFIER_CONTRACT || '0xce5845372e615Cbb46EFCc76c21051932BD8A717';
const contractABI = [
  {
    inputs: [{ internalType: 'address', name: 'verifier', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256[4]',
        name: 'input',
        type: 'uint256[4]',
      },
      {
        indexed: false,
        internalType: 'uint256[4]',
        name: 'compressedProof',
        type: 'uint256[4]',
      },
    ],
    name: 'CompressedProofVerifiedAndSaved',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256[4]',
        name: 'input',
        type: 'uint256[4]',
      },
      {
        indexed: false,
        internalType: 'uint256[8]',
        name: 'proof',
        type: 'uint256[8]',
      },
    ],
    name: 'ProofVerifiedAndSaved',
    type: 'event',
  },
  {
    inputs: [],
    name: '_verifier',
    outputs: [{ internalType: 'contract IVerifier', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint256[2]', name: 'input', type: 'uint256[2]' }],
    name: 'isProofed',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'bytes', name: 'hash', type: 'bytes' }],
    name: 'isProofedHash',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'owner',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'verifier', type: 'address' }],
    name: 'setVerifier',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint256[2]', name: 'array', type: 'uint256[2]' }],
    name: 'toHash',
    outputs: [{ internalType: 'bytes', name: '', type: 'bytes' }],
    stateMutability: 'pure',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'uint256[4]', name: 'input', type: 'uint256[4]' },
      {
        internalType: 'uint256[4]',
        name: 'proof',
        type: 'uint256[4]',
      },
    ],
    name: 'verifyAndSaveCompressedProof',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'uint256[4]', name: 'input', type: 'uint256[4]' },
      {
        internalType: 'uint256[8]',
        name: 'proof',
        type: 'uint256[8]',
      },
    ],
    name: 'verifyAndSaveProof',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
];
const contract = new web3.eth.Contract(contractABI, contractAddress);

const privateKey = process.env.PRIVATE_KEY as string;

const web3Account = web3.eth.accounts.privateKeyToAccount('0x' + privateKey);

export const executeContractCall = async (input: string[], proof: string[]) => {
  const estimateGas = await contract.methods
    .verifyAndSaveProof(input, proof)
    .estimateGas({ from: web3Account.address });

  const signedTx = await web3.eth.accounts.signTransaction(
    {
      from: web3Account.address,
      to: contractAddress,
      gas: estimateGas + estimateGas / BigInt(10),
      gasPrice: await web3.eth.getGasPrice(),
      nonce: '0x' + (await web3.eth.getTransactionCount(web3Account.address)).toString(16),
      data: contract.methods.verifyAndSaveProof(input, proof).encodeABI(),
    },
    privateKey,
  );
  try {
    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
    console.log('Transaction receipt:', receipt);
  } catch (error) {
    console.error('Transaction error:', error);
  }
};
