# iWay

High-performance QUIC / UDP / TCP / TUIC multi-protocol proxy server for
Linux, macOS, and Windows.

## Project Overview

iWay is a high-performance network proxy server written in Rust. It
supports TUIC (QUIC, UDP, TCP, and more) and is designed for secure and
efficient network forwarding and proxy scenarios, leveraging Rust’s
memory safety and async concurrency model.

GitHub Actions are used to build release binaries.

Note:

1. iWay is currently under active development. v2.1.9 is the latest
   stable release and is recommended for general use (TUIC v5 only).

2. For production deployments, it is strongly recommended to use your
   own server.crt and server.key.

## Features

- TUIC protocol support, compatible with multiple clients
- QUIC transport for low latency and high throughput
- UDP / TCP / QUIC multi-protocol forwarding
- DNS cache and custom DNS resolver support
- Authentication and session management
- Automatic port mapping when the proxy target is the server itself:

  Original Address Type | Mapped Address | Port
  --------------------- | -------------- | ----------
  IPv4                  | 127.0.0.1      | Unchanged
  IPv6                  | ::1            | Unchanged

- Highly modular and easy to extend

## Directory Structure

src/
├── config.rs                    # Configuration loader
├── lib.rs / main.rs             # Project entry point
├── authenticate/                # Authentication modules
├── dns/                         # DNS cache and resolver
├── processor/                   # Core protocol processors
│   └── tuic/                    # TUIC protocol handling
│       ├── command/             # TUIC command handling
│       └── udp_session_manager.rs
├── protocol/                    # Protocol definitions
├── server/                      # Server startup and management
└── sockets/                     # Socket wrappers

## Quick Start

1. Install Rust

   curl --proto '=https' --tlsv1.2 -sSf <https://sh.rustup.rs> | sh

2. Build the Project

   cargo build --release

3. Run the Server (development)

   cargo run --release

4. Configuration

   Edit config.toml to configure the listening address, certificates,
   keys, and protocol settings.

   Example (v2 format, protocol blocks with enabled flags):

   [trojan]
   enabled = true
   server_addr = "[::]:443"
   cert_path = "server.crt"
   key_path = "server.key"
   fallback_addr = "127.0.0.1:80"

5. Run the Release Binary

   /path/to/iway config.toml

## Dependencies

- tokio — async runtime
- quinn — QUIC protocol stack
- tuic — TUIC protocol v5 (see TUIC_V5.md)
- See Cargo.toml for the full list

## Contributing

Issues and pull requests are welcome. Please familiarize yourself with
the project structure and existing code before contributing.

## License

This project is licensed under the MIT License.
See the LICENSE file for details.
