## Running ibc-relay
### Running relayer locally

###### Prerequisites
- Go version: 1.19  
- Setup go environment
	```
	export GOROOT=/usr/local/bin/go/go-1.9
	export GOPATH=/opt/go/packages
	export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
	```
- Install goloop
	```
	go install github.com/icon-project/goloop/cmd/goloop@latest
	```


### Build relay
- Run below command to build the relay  
  ```
  make build
  ```
- To build and install the relayer binary  
  ```
  make install
  ```


### Relay configuration

Within this setup for a local relayer, we will establish the configuration of the relay with both the ICON and Archway local nodes.  

- Modify environment variables in `const.sh`.  

- Clone icon-ibc-setup repo  
  ```
  git clone https://github.com/izyak/icon-ibc-setup.git
  ```
- Start nodes
  ```
  make nodes
  ```
- Setup ICON node  
  ```
  make icon
  ```

- Setup Archway node  
  ```
  make archway
  ```

- Update relayer config file  
  ``
  ake config
  ```
- Relay config file
	<details>
	<summary>The following is an example configuration of a relayer.</summary>
	  
	```
	global:
	    api-listen-addr: :5183
	    timeout: 10s
	    memo: ""
	    light-cache-size: 20
	chains:
	    archway:
	        type: archway
	        value:
	            key-directory: /home/.relayer/keys/constantine-3
	            key: default
	            chain-id: constantine-3
	            rpc-addr: https://rpc.constantine.archway.tech:443
	            account-prefix: archway
	            keyring-backend: test
	            gas-adjustment: 1.5
	            gas-prices: 1000000000000aconst
	            min-gas-amount: 1000000
	            debug: true
	            timeout: 20s
	            block-timeout: ""
	            output-format: json
	            sign-mode: direct
	            extra-codecs: []
	            coin-type: 0
	            broadcast-mode: batch
	            ibc-handler-address: 
	            first-retry-block-after: 0
	    icon:
	        type: icon
	        value:
	            key: ""
	            chain-id: ibc-icon
	            rpc-addr: https://berlin.net.solidwallet.io/api/v3/
	            timeout: 30s
	            keystore: /home/.relayer/keystore/godWallet.json
	            password: ****
	            icon-network-id: 1
	            btp-network-id: 2
	            btp-network-type-id: 1
	            start-btp-height: 0
	            ibc-handler-address: 
	            first-retry-block-after: 0
	paths:
	    icon-archway:
	        src:
	            chain-id: 
	            client-id: 
	        dst:
	            chain-id: 
	            client-id: 
	        src-channel-filter:
	            rule: ""
	            channel-list: []
	```
	</details>	

Prior to executing the relayer, ensure that the relay configuration file is accurately and properly configured.

### Running Relayer

- Start link
  ```
  rly tx link icon-archway --client-tp=10000m --src-port mock --dst-port mock -d
  ```
- Run relayer
  ```
  rly start icon-archway
  ```
