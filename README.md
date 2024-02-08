# eth-node-handshake

Minimalistic ethereum node handshake mainly based on [devp2p](https://github.com/ethereum/devp2p) and [rust-devp2p](https://github.com/vorot93/devp2p).

Get enode of node from [here] (https://ethernodes.org/nodes) and pass it as CLI argument:
```
cargo run enode://c9d9a8656916a6303e401be2e127ef6054fc3a1f74408593d9cbdb319370c5b13ee98b0d9ef6b7f22a45bec50598a696aa4770cbb9f1109e6ef82ed4d4bea26c@13.115.79.190:30303

Connected to target adress: "13.115.79.190:30303"

Hanshake completed succesfully
 Received MAC is valid!

Hello message from target node:
Hello { protocol_version: 5, client_version: "Geth/v1.12.2-stable-bed84606/linux-amd64/go1.19.12", capabilities: [Capability { name: "eth", version: 66 }, Capability { name: "eth", version: 67 }, Capability { name: "eth", version: 68 }, Capability { name: "snap", version: 1 }], port: 0, id: PublicKey(b1c5709331dbcbd9938540741f3afc5460ef27e1e21b403e30a6166965a8d9c96ca2bed4d42ef86e9e10f1b9cb7047aa96a69805c5be452af2b7f69e0d8be93e) }
```
