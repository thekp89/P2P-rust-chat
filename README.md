# P2P Rust Chat

An encrypted peer-to-peer terminal chat application built with Rust, `libp2p`, and `ratatui`.

## Features

- **P2P Networking**: Uses `libp2p` with Gossipsub for message broadcasting and mDNS for local network discovery.
- **End-to-End Encryption**: Secure communication using X25519 Diffie-Hellman key exchange and ChaCha20Poly1305 for message encryption.
- **TUI (Terminal User Interface)**: A modern terminal interface built with `ratatui` and `crossterm`.
- **Modular Design**: Clean codebase split into crypto, network, and UI modules.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/thekp89/P2P-rust-chat.git
   cd P2P-rust-chat
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

## Usage

You can run the chat application using `cargo run`.

### Starting a Chat Instance

Basic usage:
```bash
cargo run -- -u User1
```

### Options

- `-u, --username <USERNAME>`: Set your display name (default: "anonymous").
- `-p, --port <PORT>`: Port to listen on (default: 0, which picks a random available port).
- `-m, --mdns`: Enable mDNS discovery to automatically find peers on the local network.
- `-c, --connect <IP:PORT>`: Manually connect to a specific peer.
- `--log-level <LEVEL>`: Set logging level (trace, debug, info, warn, error).

### Examples

**On Machine A (Starting and listening):**
```bash
cargo run -- -u Alice -p 9000 -m
```

**On Machine B (Connecting to Alice):**
```bash
cargo run -- -u Bob -c 192.168.1.10:9000 -m
```

### Controls

- **Enter**: Send your message.
- **Backspace**: Delete character in the input field.
- **'q'**: Quit the application.

## Security

Messages are encrypted using ChaCha20Poly1305 with keys derived from an X25519 ephemeral Diffie-Hellman handshake. Every time a connection is established, a new shared secret is negotiated.
