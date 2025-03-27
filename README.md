# Paramiko Insecure SSH Client/Server Demo

This project demonstrates an **insecure** SSH implementation using Paramiko with a custom transport that forces 'none' cipher and MAC algorithms. 

## Features

- Custom Paramiko transport that forces 'none' cipher and MAC
- SSH server that accepts 'none' authentication
- Detailed logging of SSH protocol negotiation
- Demonstration of basic SSH client/server communication

## Security Considerations

- No encryption (cipher set to 'none')
- No message authentication (MAC set to 'none')
- Accepts any client with 'none' authentication
- Uses temporary host keys (not persistent)
- No host key verification on client side

## Requirements

- Python 3.6+
- Paramiko (`pip install paramiko`)
- cryptography (for RSA key generation)

## Installation

```bash
pip install paramiko cryptography
```

## Usage

1. First start the server in one terminal:
```bash
python ssh_server.py
```

2. Then run the client in another terminal:
```bash
python ssh_client.py
```

## How It Works

### Server (`ssh_server.py`)
- Creates a temporary RSA host key
- Listens on port 2200
- Implements a minimal `ServerInterface` that:
  - Allows 'none' authentication
  - Rejects other auth methods
  - Sends a "Hello World" message to connected clients

### Client (`ssh_client.py`)
- Connects to localhost:2200
- Uses custom transport to force 'none' cipher/MAC
- Authenticates with 'none' method
- Receives and displays server message

### Custom Transport (`none_cipher_transport.py`)
- Extends Paramiko's Transport class
- Forces 'none' cipher and MAC to be preferred
- Bypasses normal security mechanisms

## Files

- `ssh_client.py` - Insecure SSH client implementation
- `ssh_server.py` - Insecure SSH server implementation  
- `none_cipher_transport.py` - Custom transport forcing 'none' cipher
- `logging_config.py` - Shared logging configuration


