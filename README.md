# Task

Design and write the code that implements the ZKP Chaum–Pedersen Protocol outlined in ["Cryptography: An Introduction (3rd Edition) Nigel Smart"](https://www.cs.umd.edu/~waa/414-F11/IntroToCrypto.pdf) page 377 section "3. Sigma Protocols" subsection "3.2. Chaum–Pedersen Protocol.". Solution should be implemented as server and client using gRPC protocol according to the provided interface described in the './proto/auth.proto' file. The code should implement very simple server and client applications.

# Approach

- Understand and test Chaum–Pedersen protocol
- Implement useable protcol service
- Understand gRPC implementation in Rust
- Implement basic gRPC client
- Implement basic gRPC server with simple data access layer

At this point I did it hackathon style. Meaning choosing the fastest way to the desired result. From this point on I concentrated on the aspects relevant for develoing production ready code.

- Use traits to abstract structs in preparation for testing
- Write integration tests for core use case. This allows me to do refactorings without breaking it.

# Improvments

- Integration tests as gherkin tests with [cucumber-rs](https://cucumber-rs.github.io/cucumber/current/)