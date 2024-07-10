# Mainnet Relaying Guide

Get libwasmvm library

```sh
wget https://github.com/CosmWasm/wasmvm/releases/download/v1.5.0/libwasmvm.x86_64.so
sudo mv libwasmvm.x86_64.so /usr/lib
```

Now, let's get started with the relay portion.

1. Get the version of latest binary of the relay from the github assets from this [repo](https://github.com/icon-project/relayer/v2)
2. Then, download the relay binary from the assets of this release on your machine.

```sh
export CURR_VERSION=1.1.1
wget https://github.com/icon-project/relayer/v2/releases/download/v${CURR_VERSION}/ibc-relay_${CURR_VERSION}_linux_amd64.tar.gz
tar -xvzf ibc-relay_${CURR_VERSION}_linux_amd64.tar.gz
cd ibc-relay_${CURR_VERSION}_linux_amd64
sudo mv rly /usr/local/bin
```

3. Copy this config file. You might need to change the key directory and key as per your requirements. Check steps to setup keys in the main README file.

```yaml
global:
  api-listen-addr: :5183
  timeout: 10s
  memo: ""
  light-cache-size: 20
chains:
  archway:
    type: wasm
    value:
      key-directory: /home/ubuntu/.relayer/keys/archway-1
      key: relayWallet
      chain-id: archway-1
      rpc-addr: https://rpc.mainnet.archway.io:443
      account-prefix: archway
      keyring-backend: test
      gas-adjustment: 1.5
      gas-prices: 900000000000aarch
      min-gas-amount: 1000000
      debug: true
      timeout: 20s
      block-timeout: ""
      output-format: json
      sign-mode: direct
      extra-codecs: []
      coin-type: 0
      broadcast-mode: batch
      ibc-handler-address: archway1rujqm6c555jv4zaa6q0x0fcc7mk4ca4zgyg9gt3xhzzw0933g63qk4v0zl
      first-retry-block-after: 0
      start-height: 0
      block-interval: 4000
  icon:
    type: icon
    value:
      key-directory: /home/ubuntu/.relayer/keys
      chain-id: mainnet
      rpc-addr: https://ctz.solidwallet.io/api/v3/
      timeout: 30s
      keystore: relayWallet
      password: SkLb3PX8GiHOsMy84L73pZYXA
      icon-network-id: 1
      btp-network-id: 1
      btp-network-type-id: 1
      start-height: 0
      ibc-handler-address: cx622bbab73698f37dbef53955fd3decffeb0b0c16
      first-retry-block-after: 0
      block-interval: 2000
  neutron:
    type: wasm
    value:
      key-directory: /home/ubuntu/.relayer/keys/neutron-1
      key: relayWallet
      chain-id: neutron-1
      rpc-addr: https://rpc-kralum.neutron-1.neutron.org:443
      account-prefix: neutron
      keyring-backend: test
      gas-adjustment: 1.5
      gas-prices: 0.5untrn
      min-gas-amount: 1000000
      debug: true
      timeout: 20s
      block-timeout: ""
      output-format: json
      sign-mode: direct
      extra-codecs: []
      coin-type: 0
      broadcast-mode: batch
      ibc-handler-address: neutron1fsxayjp6djfk00v9m79fuuku885a4c6kz7sj9wn0yw0wv4luntmq00rty5
      first-retry-block-after: 0
      start-height: 0
      block-interval: 2000
paths:
  icon-archway:
    src:
      chain-id: mainnet
      client-id: 07-tendermint-0
      connection-id: connection-0
    dst:
      chain-id: archway-1
      client-id: iconclient-0
      connection-id: connection-0
    src-channel-filter:
      rule: ""
      channel-list: []
  icon-neutron:
    src:
      chain-id: mainnet
      client-id: 07-tendermint-2
      connection-id: connection-2
    dst:
      chain-id: neutron-1
      client-id: iconclient-1
      connection-id: connection-0
    src-channel-filter:
      rule: ""
      channel-list: []
```

4. Start the relay with the following command.

```sh
rly start icon-archway # start icon-archway relay
rly start icon-neutron # start icon-neutron relay
rly start # start both relay
```
