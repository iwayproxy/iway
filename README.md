# iWay

High-Performance QUIC/UDP/TCP/TUIC Multi-Protocol Proxy Server For Linux, MacOS And Windows.

## Project Overview

iWay is a high-performance network proxy server written in Rust, supporting TUIC (QUIC, UDP, TCP, and more). It is designed for secure and efficient network forwarding and proxy scenarios, leveraging Rust's safety and concurrency with an async programming model.

Github Action Builds For Releases.

**Note:**

1. iWay is currently under active development. V2.1.9 is the latest stable release, recommended for general use(supports only TUIC v5).

2. Strongly recommended to use your own server.crt and server.key for security.

## Features

- TUIC protocol support, compatible with multiple clients
- QUIC transport for low latency and high throughput
- UDP/TCP/QUIC multi-protocol forwarding
- DNS cache and custom DNS resolver support
- Authentication and session management
- If the proxy target address is the proxy server itself, port mapping will be performed as follows:

  | Original Address Type | Mapped Address   | Port   |
  |----------------------|------------------|--------|
  | IPv4                 | 127.0.0.1        | Unchanged |
  | IPv6                 | ::1              | Unchanged |

- Highly modular and easy to extend

## Directory Structure

```text
src/
├── config.rs                # Configuration loader
├── lib.rs / main.rs         # Project entry point
├── authenticate/            # Authentication modules
├── dns/                     # DNS cache and resolver
├── processor/               # Core protocol processors
│   └── tuic/                # TUIC protocol handling
│       ├── command/         # TUIC command handling
│       └── udp_session_manager.rs  # UDP session management
├── protocol/                # Protocol definitions
├── server/                  # Server startup and management
└── sockets/                 # Socket wrappers
```

## Quick Start

1. **Install Rust**

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Build the Project**

   ```sh
   cargo build --release
   ```

3. **Run the Server**

   ```sh
   cargo run --release
   ```

4. **Configuration**

   Edit `config.toml` to set the listening port, certificate, key, and other parameters as needed.

5. **Run Command**

   ```sh
   <path_to_iway>/iway config.toml
   ```

## Dependencies

- [tokio](https://tokio.rs/) async runtime
- [quinn](https://github.com/quinn-rs/quinn) QUIC protocol stack
- [tuic](https://github.com/EAimTY/tuic) protocol V5 (see [TUIC_V5.md](./TUIC_V5.md))
- See `Cargo.toml` for more

## Contributing

Issues and PRs are welcome! Please read the code structure and comments before contributing.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
