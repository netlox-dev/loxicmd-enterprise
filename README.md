# loxicmd

![build workflow](https://github.com/loxilb-io/loxicmd/actions/workflows/build.yml/badge.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/loxilb-io/loxicmd)
![License](https://img.shields.io/github/license/loxilb-io/loxicmd)

## Overview

**loxicmd** is a powerful command-line interface (CLI) tool for managing and interacting with [loxilb](https://github.com/loxilb-io/loxilb) — a cloud-native, eBPF-based load balancer. It provides comprehensive control over your load balancing infrastructure, enabling configuration and monitoring from the terminal.

## Features
**Load Balancer Management**
- Create, delete, and retrieve service-type external load balancers
- Support for multiple load balancing algorithms and protocols

**Network Monitoring**
- Port/interface dump inspection for loxilb and Docker containers
- Real-time connection tracking (TCP/UDP/ICMP/SCTP)
- Network neighbor and route management

**Advanced Configuration**
- QoS policy management
- VLAN and VXLAN configuration
- Firewall rule management
- BGP neighbor configuration
- Session management and monitoring

**Infrastructure Management**
- BFD (Bidirectional Forwarding Detection) support
- Mirror configuration for traffic analysis
- Endpoint and IP address management

## Installation

### Prerequisites

- Go 1.19 or later
- Make utility

### Building from Source

1. **Clone the repository**
   ```bash
   git clone https://github.com/loxilb-io/loxicmd.git
   cd loxicmd
   ```

2. **Install dependencies**
   ```bash
   go get .
   ```

3. **Build the binary**
   ```bash
   make
   ```

4. **Verify installation**
   ```bash
   ./loxicmd version
   ```

### Installing Pre-built Binaries

Download the latest release from the [releases page](https://github.com/loxilb-io/loxicmd/releases) and add it to your PATH.

## Quick Start

### Basic Load Balancer Operations

1. **List all load balancers**
   ```bash
   ./loxicmd get lb
   ```

2. **Create a new load balancer**
   ```bash
   ./loxicmd create lb 192.168.0.200 --tcp=80:32015 --endpoints=10.212.0.1:1,10.212.0.2:1,10.212.0.3:1
   ```

3. **Delete a load balancer**
   ```bash
   ./loxicmd delete lb 192.168.1.100 --tcp=80
   ```


### Output Formatting

Get results in various formats for automation or readability, such as `json` or `wide`:

```bash
./loxicmd get lb --output=json
./loxicmd get lb --output=wide
./loxicmd get lb -o json
./loxicmd get lb -o wide
```

## Command Reference

### Global Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--server` | `-s` | loxilb API server address | `-s 192.168.1.10` |
| `--port` | `-p` | loxilb API server port | `-p 8080` |
| `--output` | `-o` | Output format (json, yaml, table) | `-o json` |
| `--help` | `-h` | Show help information | `-h` |

### Available Commands
For more detailed command descriptions and examples, please refer to the [documentation in loxilbdocs](https://github.com/loxilb-io/loxilbdocs/blob/main/docs/cmd.md).

## Help and Documentation

Get comprehensive help for any command:

```bash
# General help
./loxicmd help

# Command-specific help
./loxicmd help create lb
./loxicmd get lb --help
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## Related Projects

- [loxilb](https://github.com/loxilb-io/loxilb) - The main loxilb load balancer

