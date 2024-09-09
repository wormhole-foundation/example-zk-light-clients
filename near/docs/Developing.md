
# Developing

## HTTP Backend service

### Prerequisites

1. **Node.js**: Ensure you have Node.js installed. The recommended version is the latest LTS version, which can be downloaded from [Node.js official website](https://nodejs.org/).

2. **npm (Node Package Manager)**: npm is installed with Node.js. You can verify the installation by running:
```bash
node -v
npm -v
```
3. TypeScript: This project uses TypeScript, which is included in the devDependencies.

4. `ts-node-dev`: This is used to run TypeScript files with node. It is included in the devDependencies.

5. Prisma: Ensure you have Prisma CLI installed globally. You can install it using:
```bash
npm install -g prisma
```
### Project Setup

1. Install Dependencies: Install all required dependencies using yarn.
```bash
npm install
```
2. Environment Variables: Ensure you have a .env file at the root of the project with the necessary environment variables configured. You can use the dotenv package to manage environment variables.

### Database Setup

1. Database Migration: Run the following command to apply database migrations.
```bash
npm run db:migrate
```
2. Database Push: Push the Prisma schema state to the database.
```bash
npm run db:push
```

### Development Workflow

1. Start the Server: Run the server using the following command.
```bash
npm start
```
2. Formatting: Ensure your code is properly formatted using Prettier.
```bash
npm run format
```
3. Linting: Check your code for linting errors using ESLint.
```bash
npm run lint
```
4. Format Check: Verify if the code follows Prettier formatting.
```bash
npm run format-check
```

### Software Versions

- Node.js: Recommended LTS version
- TypeScript: ^4.9.5
- ts-node-dev: ^2.0.0
- Prisma: ^5.8.1
- Prettier: ^3.2.5
- ESLint: ^8.57.0
- Express: ^4.18.2
- web3: ^4.7.0

Ensure to keep the dependencies updated by regularly checking for updates in the package.json file.


## Rust

 1. Install dependencies required for Rust and libraries: gfgf
```bash
sudo apt install curl
sudo apt install wget
sudo apt install build-essential
sudo apt install pkg-config
sudo apt install libssl-dev
```
 2. Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup default nightly
```
 3. Export NATS url env:
```
export NATS_URL=nats://127.0.0.1:4222
```
> [!NOTE]
> Last stage, run after `NATS` setup
 4. Run queue-processor (block proving) and queue-prover (signatures):
```
cd near
cargo run --release --bin queue-prover
cargo run --release --bin queue-processor
```

## Go

 1. Install Go for GNARK service:
 ```bash
sudo rm -rf /usr/local/go && sudo wget https://golang.org/dl/go1.22.3.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz && sudo rm go1.22.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```
 2. Generate keys, contract for Gnark verification, files will be stored in `api-build` folder:
```bash
cd near/gnark-plonky2-verifier
USE_BIT_DECOMPOSITION_RANGE_CHECK=true go run main.go compile --dir testdata/test_circuit
```
 3. Run `gnark-wrapper` service for handling proof requests:
```bash
USE_BIT_DECOMPOSITION_RANGE_CHECK=true go run main.go web-api --dir testdata/test_circuit
```

## Nats

Install Nats binary and create configuration file with jetstream:
```bash
mkdir nats
cd nats
curl -sf https://binaries.nats.dev/nats-io/nats-server/v2@latest | sh
printf "%s\n" "listen: 127.0.0.1:4222" "# js.conf" "jetstream {" "   store_dir=nats" "}" > js.conf
./nats-server -c js.conf
```