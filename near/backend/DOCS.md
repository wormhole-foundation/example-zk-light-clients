# Instructions to Run the `prover-backend` 

## Prerequisites

1. **Node.js**: Ensure you have Node.js installed. The recommended version is the latest LTS version, which can be downloaded from [Node.js official website](https://nodejs.org/).

2. **npm (Node Package Manager)**: npm is installed with Node.js. You can verify the installation by running:
   ```sh
   node -v
   npm -v
3. TypeScript: This project uses TypeScript, which is included in the devDependencies.

4. `ts-node-dev`: This is used to run TypeScript files with node. It is included in the devDependencies.

5. Prisma: Ensure you have Prisma CLI installed globally. You can install it using:
   ```sh
   npm install -g prisma

## Project Setup
1. Install Dependencies: Install all required dependencies using yarn.
   ```sh
   npm install
2. Environment Variables: Ensure you have a .env file at the root of the project with the necessary environment variables configured. You can use the dotenv package to manage environment variables.

## Database Setup
1. Database Migration: Run the following command to apply database migrations.
   ```sh
   npm run db:migrate
2. Database Push: Push the Prisma schema state to the database.
   ```sh
    npm run db:push

## Development Workflow
1. Start the Server: Run the server using the following command.
   ```sh
    npm start
2. Formatting: Ensure your code is properly formatted using Prettier.
   ```sh
    npm run format
3. Linting: Check your code for linting errors using ESLint.
    ```sh
    npm run lint
4. Format Check: Verify if the code follows Prettier formatting.
    ```sh
    npm run format-check

## Software Versions
- Node.js: Recommended LTS version
- TypeScript: ^4.9.5
- ts-node-dev: ^2.0.0
- Prisma: ^5.8.1
- Prettier: ^3.2.5
- ESLint: ^8.57.0
- Express: ^4.18.2
- web3: ^4.7.0

Ensure to keep the dependencies updated by regularly checking for updates in the package.json file.





