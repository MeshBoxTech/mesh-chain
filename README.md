# mesh-chain

mesh-chain is an [Spectrum-compatible](https://github.com/SmartMeshFoundation/Spectrum) project. It uses a new consensus and new block reward for meshbox ecosystem.

Since the list of signers is 21, it is recommended that the confirmation number of general transfer transaction block be set to 21 (one round), and that of exchange block be set to 42 (two rounds).

## List of Chain ID's:
| Chain(s)    |  CHAIN_ID  | 
| ----------  | :-----------:| 
| mainnet     | 20220430     | 
| testnet     | 2023         | 

## Warning

We suggest that the GasPrice should not be less than 18Gwei, otherwise the transaction may not be packaged into the block.

## Build the source 

Building mesh-chain requires both a Go (version 1.9.2 or later) and a C compiler. You can install them using your favourite package manager. And you can view the detail installation and running steps on this [page](https://github.com/MeshBoxTech/mesh-chain/wiki/Building-Specturm).

## Run node 

    $ ./build/bin/smc console
    
## Create new account
    Users can create new account:

    > personal.newAccount()

## Get your own miner id

    Every node has it's own miner id, you can run getMiner() function to get that id:

    > tribe.getMiner() 
    
## Bind your own miner id to wallet address

    Users can bind their miner ID to a wallet address:

    > tribe.bind("account","passwd") 
    
    Or Users can only generate binding signatures at the terminal:
    
    > tribe.bindSign("account") 
    
## More functions
    Users can input tribe to view:
    
    > tribe
    
## Security-related 
  
### Encrypt your nodekey

     $ ./build/bin/smc security --passwd
     
### Decrypt your nodekey

     $ ./build/bin/smc security --unlock
     

