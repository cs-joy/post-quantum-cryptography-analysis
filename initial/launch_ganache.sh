#!/bin/bash

# Kill any process using port 8545
kill_port() {
    lsof -i:8545 -t | xargs -r kill -9
    sleep 2
}

# Kill existing process on port 8545
echo "Checking for existing process on port 8545..."
kill_port

# Start Ganache with high account balance and gas
ganache \
    --port 8545 \
    --gas-limit 100000000 \
    --accounts 10 \
    --account_keys_path "keys.json" \
    --mnemonic "test test test test test test test test test test test junk" \
    --chain.networkId 1337 \
    --chain.chainId 1337 \
    --chain.hardfork "london" \
    --wallet.defaultBalance 10000