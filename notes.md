# Anonymous Communication Systems (Onion Routing)

**Algorithm**: *Nested multi-layer encryption packet wrapper (Layered AES/RSA routing)*
**Objective**: *Conceal the origin, destination, and routing path of internet traffic through intermediary proxy nodes*
**Application Scenario**: *A mini-Tor terminal chat client where a message from a client is wrapped in 3 layers of encryption, passed sequentially through 3 simulated proxy nodes, and delivered anonymously to a receiver*

Client to Client (e2e or p2p) Chat Client
3 Layers of Encryption
3 Simulated Proxy Nodes (Same way that Onion Routing behaves)


``` bash
# Run to activate python Environment
source .venv/bin/activate
```
