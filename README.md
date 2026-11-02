# P2P Rust Chat

An encrypted peer-to-peer terminal chat application built with Rust, `libp2p`, and `ratatui`.

## Features

- **P2P Networking**: Uses `libp2p` with Gossipsub for multicast message broadcasting and optional mDNS for local network discovery.
- **End-to-End Encryption (E2EE)**: Secure communication combining X25519 Diffie-Hellman key exchange, Ed25519 signature authentication, and ChaCha20Poly1305 multi-recipient envelope encryption.
- **TUI (Terminal User Interface)**: Modern, responsive split-screen terminal interface built with `ratatui` and `crossterm`.
- **Peer & Status Sidebar**: Real-time view of connected peers, security status (🔒 E2EE / ⏳ Handshake), local node identity, and listening ports.
- **Scrollable Chat & Text Editing**: Full cursor movement, history scrolling (`PageUp`/`PageDown`), and text editing controls.
- **Interactive Slash Commands**: In-chat commands (`/help`, `/peers`, `/connect`, `/clear`, `/quit`).
- **Crash-Resilient Terminal**: Safe panic hook ensures the terminal state is always restored even if an error occurs.
- **Modular Design**: Clean codebase split into crypto, network, and UI modules with comprehensive unit tests.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (version 1.70+ recommended)
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

3. Run the automated test suite:
   ```bash
   cargo test
   ```

## Usage

You can run the chat application using `cargo run`.

### Starting a Chat Instance

Basic usage (launches the setup menu):
```bash
cargo run -- -u Alice
```

Launch directly into chat without the setup menu:
```bash
cargo run -- -u Alice -p 9000 -m --no-menu
```

### Command-Line Options

- `-u, --username <USERNAME>`: Set your display name (default: "anonymous").
- `-p, --port <PORT>`: Port to listen on (default: 0, which picks a random available port).
- `-m, --mdns`: Enable mDNS discovery to automatically find peers on the local network.
- `-c, --connect <IP:PORT or Multiaddr>`: Connect to a specific peer at startup.
- `--no-menu`: Skip setup menu and jump straight into chat.
- `--log-file <PATH>`: Destination for logs (default: `chat.log` to prevent TUI screen corruption).
- `--log-level <LEVEL>`: Set logging level (`trace`, `debug`, `info`, `warn`, `error`).

### Examples

**On Machine A (Starting and listening):**
```bash
cargo run -- -u Alice -p 9000 -m
```

**On Machine B (Connecting to Alice):**
```bash
cargo run -- -u Bob -c 192.168.1.10:9000 -m
```

### In-App Controls & Navigation

- **Enter**: Send message or execute command.
- **Left / Right**: Move cursor horizontally within your message.
- **Home / End**: Jump to start / end of your message.
- **Backspace / Delete**: Delete character before / at the cursor.
- **PageUp / PageDown** (or **Up / Down**): Scroll chat history.
- **Esc** or **Ctrl+C**: Quit the application safely.

### Slash Commands

Type these directly in the chat message input:

- `/help` - Show available commands.
- `/peers` - List all connected peers with their encryption status.
- `/connect <IP:PORT or Multiaddr>` - Dial a peer dynamically while chat is running.
- `/clear` - Clear chat history on your screen.
- `/quit` or `/exit` - Disconnect and exit.

## Security Architecture

1. **Authenticated Key Exchange**: Handshake payloads contain X25519 public keys signed by each peer's Ed25519 identity key (`PeerId`), preventing Man-In-The-Middle (MITM) attacks.
2. **Multi-Recipient Envelope Encryption**: When broadcasting a message over Gossipsub, each chat payload is encrypted with a random one-time 256-bit symmetric key (`K_msg`). `K_msg` is encrypted separately for each authorized peer using that peer's derived shared secret. Peers not in the recipient list cannot decrypt the payload.
3. **Transport Layer Encryption**: libp2p TCP connections utilize the Noise protocol (XX handshake) with Yamux multiplexing.
