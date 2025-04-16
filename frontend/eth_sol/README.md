# Eth-Sol-Frontend for OpenVector Coprocessor

This is the frontend for the ethereum compatible networks for the OpenVector Coprocessor. It provides a solidity library to interact with the OpenVector Coprocessor network and do confidential computing.

### Features

- Adds support for confidential computing to existing Ethereum compatible networks.
- Provides a simple and easy to use API for developers to interact with the OpenVector Coprocessor network.

### Installation

This project uses `Hardhat` and `NPM` for development. To install the project, run the following command:

```bash
npm install
```

### Usage

To use the library, you need to import the library in your smart contract and then use the functions provided by the library. Remember to update the COFHEExecutorAddress to the required exectuor address.

```solidity
pragma solidity ^0.8.0;

import "../lib.sol";
```

Refer to example contract `cov_token.sol` in `contracts/exampls` directory for more details on how to use the library. The example contract is a confidential/encrypted token contract that uses the OpenVector Coprocessor network to do confidential computing.