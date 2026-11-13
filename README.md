# TLS10Proxy

## Description

TLS10Proxy is a specialized HTTP and HTTPS proxy server designed to provide internet access to legacy devices that only support outdated cryptographic standards, such as TLS 1.0 and SHA-1 certificates.   
It acts as a man-in-the-middle proxy, dynamically generating server certificates signed by an internal Certificate Authority to establish secure downstream connections with older clients.

The proxy includes a built-in Basic Authentication mechanism with a unique captive portal fallback feature.   
This feature binds authorized clients to their IP subnet and User-Agent string, allowing subsequent requests from the same subnet and application to pass through without requiring repeated authentication headers, which many legacy clients fail to send.  

Additionally, TLS10Proxy provides Fail2ban integration to automatically block IP addresses that repeatedly fail authentication, and it can chain outgoing connections through an upstream HTTP, HTTPS, SOCKS5, or SOCKS5h proxy.

## Requirements

To build, install, and fully utilize TLS10Proxy, the following components are required:

*   **Go Toolchain**: Required to compile the source code into a binary executable (https://go.dev/doc/install).
*   **Systemd**: Required to install and manage the background service on Linux distributions.
*   **Fail2ban** (Optional): Required if you wish to install the provided jail and filter rules to protect the proxy from brute-force attacks.
*   **libwbxml Utilities** (Optional): Required only if you need to generate WBXML provisioning files for Nokia S40 devices (provided in the `s40-config-generator` directory).

## Installation

### Building from Source

Clone the repository and build the binary using the provided Makefile:

```bash
make build
```

### System Service Installation

To install the binary to `/opt/tls10proxy` and register it as a systemd service, run:

```bash
sudo make install
```

To remove the service and the binary, run:

```bash
sudo make uninstall
```

### Fail2ban Integration

To install the Fail2ban filters and jail configuration to protect the proxy from unauthorized access attempts:

```bash
sudo make install-fail2ban
```

To remove the Fail2ban configuration:

```bash
sudo make uninstall-fail2ban
```

### Nokia S40 Configuration Generator

To configure a Nokia S40 device to use the proxy, you can generate a WBXML provisioning file. Ensure `libwbxml2-utils` (or the equivalent package for your distribution) is installed on your system, then run the generator script:

```bash
cd s40-config-generator
chmod +x gen.sh
./gen.sh
```

Follow the interactive prompts to provide the configuration name, proxy IP, port, APN, and homepage URL. Transfer the generated `.prov` file to the device via Bluetooth and activate it. After activation, visit `http://cert.install` in the device's browser to download and install the proxy's root CA certificate.

## Command Line Parameters

The proxy accepts the following command line flags:

*   `-bind` (string): The network address and port the proxy will listen on. (Default: `127.0.0.1:5000`)
*   `-auth` (string): The credentials required for client authorization, formatted as `user:pass`. Leave blank to disable authentication. (Default: `""`)
*   `-auth-captive` (boolean): Enables the captive portal fallback mechanism. When enabled, the proxy binds authorized clients to their IP subnet and User-Agent, bypassing authentication for subsequent requests from the same context. (Default: `true`)
*   `-captive-subnet` (integer): The CIDR subnet mask value (0-32) used for the IP subnet binding in the captive portal fallback mechanism. (Default: `16`)
*   `-log-requests` (boolean): Enables or disables the logging of incoming proxy requests. (Default: `true`)
*   `-proxy` (string): Specifies an upstream proxy to use for all outgoing connections. Supported protocols are HTTP, HTTPS, SOCKS5, and SOCKS5h. Format: `<protocol>://[login:password@]host[:port]`. Examples: `http://user:password@192.168.1.1:3128`, `socks5://10.0.0.1:1080`. (Default: `""`)