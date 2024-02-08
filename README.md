# Ethereum node handshake

Minimalistic ethereum node handshake mainly based on [devp2p](https://github.com/ethereum/devp2p) and [rust-devp2p](https://github.com/vorot93/devp2p).

Get enode of node from [here](https://ethernodes.org/nodes) and pass it as CLI argument:
```
cargo run enode://5eadf96217fa7a71010a709a7aceb4c0c541d7123865d430854ca1207e84d55242cfb34e99be7de213587db643de9a7f1ee3202a93d9fbfab58610ef9668a4b4@44.200.140.248:30303
    Finished dev [unoptimized + debuginfo] target(s) in 0.28s
     Running `target/debug/eth-node-handshake 'enode://5eadf96217fa7a71010a709a7aceb4c0c541d7123865d430854ca1207e84d55242cfb34e99be7de213587db643de9a7f1ee3202a93d9fbfab58610ef9668a4b4@44.200.140.248:30303'`
Connected to target adress: "44.200.140.248:30303"

Hanshake completed succesfully
 Received MAC is valid!

Hello message from target node:
Hello { protocol_version: 5, client_version: "Geth/v1.13.4-stable-3f907d6a/linux-amd64/go1.21.3", capabilities: [Capability { name: "eth", version: 67 }, Capability { name: "eth", version: 68 }, Capability { name: "snap", version: 1 }], port: 0, id: PublicKey(52d5847e20a14c8530d4653812d741c5c0b4ce7a9a700a01717afa1762f9ad5eb4a46896ef1086b5fafbd9932a20e31e7f9ade43b67d5813e27dbe994eb3cf42) }
```

TODO for the future:
- Geth nodes are working fine but others don't, debug why is that
- Add more tests
- Improve code structure to handle different versions of the protocol
- Sometimes first handshake works but the second doesn't, debug why is that