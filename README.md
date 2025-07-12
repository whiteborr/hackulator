# Minimal OpenVPN Implementation in Python

This is a cutdown version of OpenVPN implemented in Python, focusing on the essential CLI components needed to establish connectivity using an OVPN configuration file.

## Features

- **Configuration Parsing**: Reads and parses standard .ovpn configuration files
- **Basic Protocol Support**: Handles UDP/TCP connections to OpenVPN servers
- **TLS Handshake**: Simplified TLS connection establishment
- **State Management**: Tracks connection states (CONNECTING, AUTH, CONNECTED, etc.)
- **Logging**: Configurable verbosity levels for debugging
- **Certificate Support**: Basic support for CA, client certificates, and keys

## Limitations

This is a **minimal implementation** for educational/demonstration purposes:

- **No actual VPN tunnel creation** (would require root/admin privileges and TUN/TAP interface management)
- **Simplified TLS verification** (production use requires proper certificate validation)
- **No data channel encryption/decryption**
- **No compression support** (comp-lzo parsing only)
- **No advanced features** like routing, DNS, or network configuration
- **Limited protocol support** (basic handshake only)

## Usage

### Basic Usage

```bash
python openvpn_minimal.py --config example.ovpn
```

### With Verbose Logging

```bash
python openvpn_minimal.py --config example.ovpn --verb 4
```

### Command Line Options

- `--config FILE`: OpenVPN configuration file (.ovpn) [required]
- `--verb LEVEL`: Verbosity level 0-9 (default: 1)
- `--version`: Show version information

## Configuration File Support

The implementation supports these common .ovpn directives:

### Connection Settings
- `remote <host> <port> <protocol>`
- `port <port>`
- `proto <udp|tcp>`

### Device Settings
- `dev <tun|tap>`

### Authentication
- `ca <ca-file>`
- `cert <cert-file>`
- `key <key-file>`
- `auth-user-pass [file]`

### Encryption
- `cipher <cipher>`
- `auth <digest>`

### Other
- `comp-lzo`
- `verb <level>`
- `remote-cert-tls server`

## Professional Features

### Local DNS Server (Professional/Enterprise)

The application includes a built-in DNS server for Professional and Enterprise license holders:

- **Custom DNS Records**: Create A, AAAA, and CNAME records
- **Testing Environment**: Simulate DNS environments for penetration testing
- **Tool Integration**: Use 'LocalDNS' in any DNS tool to query the local server
- **Management Interface**: User-friendly interface for record management
- **Auto-persistence**: Records are automatically saved and restored

Access via: **Professional Features → Local DNS Server**

### Inline Certificates
Supports inline certificates/keys:
```
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
```

## Example Configuration

See `example.ovpn` for a sample configuration file.

## Architecture

The implementation consists of several key components:

### ConfigParser
- Parses .ovpn files
- Handles inline certificates
- Supports common OpenVPN directives

### OpenvpnPacket
- Basic OpenVPN packet structure
- Packet serialization/deserialization
- Protocol opcodes (HARD_RESET, CONTROL, DATA, etc.)

### TLSConnection
- SSL/TLS context management
- Certificate loading (simplified)

### OpenvpnClient
- Main client implementation
- Connection state management
- Basic handshake protocol
- Logging system

## Development

To extend this implementation:

1. **Add proper TUN/TAP interface management** for actual VPN functionality
2. **Implement full TLS verification** with proper certificate chain validation
3. **Add data channel crypto** for packet encryption/decryption
4. **Implement routing and network configuration**
5. **Add support for more OpenVPN features** (compression, fragmentation, etc.)

## Security Notice

This implementation is for **educational purposes only**. For production use:

- Use the official OpenVPN client
- Implement proper certificate validation
- Add comprehensive error handling
- Include security hardening measures

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)

## License

This minimal implementation is provided as-is for educational purposes.