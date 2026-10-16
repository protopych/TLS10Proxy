#!/bin/bash

# WBXML Provisioning Proxy Config S40 Helper Script

set -e

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for octet in "${BASH_REMATCH[@]:1}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0
    fi
    return 1
}

validate_homepage() {
    local url="$1"
    if [[ "$url" =~ ^https?://.+ ]]; then
        return 0
    fi
    return 1
}

if ! command -v xml2wbxml &> /dev/null; then
    echo "Error: The tool 'xml2wbxml' is not installed or not found in PATH."
    echo "Please install the libwbxml utilities. Example commands:"
    echo "  Ubuntu/Debian: sudo apt-get install libwbxml2-utils"
    echo "  CentOS/RHEL:   sudo dnf install libwbxml"
    echo "  macOS:         brew install libwbxml"
    exit 1
fi

if [ ! -f "template.xml" ]; then
    echo "Error: template.xml not found in the current directory."
    exit 1
fi

if [ "$#" -eq 5 ]; then
    CONFIG_NAME="$1"
    PORT="$2"
    IP="$3"
    APN="$4"
    HOMEPAGE="$5"
else
    echo "Entering interactive mode. Please provide the required parameters."
    read -r -p "Configuration Name (CONFIG-NAME): " CONFIG_NAME
    read -r -p "Port (PORT): " PORT
    read -r -p "IP Address (IP): " IP
    read -r -p "Access Point Name (APN) [internet]: " APN
    read -r -p "Homepage URL (HOMEPAGE) [http://example.com]: " HOMEPAGE

    # Apply default values if left blank
    APN="${APN:-internet}"
    HOMEPAGE="${HOMEPAGE:-http://example.com}"
fi

if [ -z "$CONFIG_NAME" ]; then
    echo "Error: Configuration Name cannot be empty."
    exit 1
fi

if ! validate_port "$PORT"; then
    echo "Error: Invalid port number. Must be an integer between 1 and 65535."
    exit 1
fi

if ! validate_ip "$IP"; then
    echo "Error: Invalid IPv4 address format."
    exit 1
fi

if [ -z "$APN" ]; then
    echo "Error: APN cannot be empty."
    exit 1
fi

if ! validate_homepage "$HOMEPAGE"; then
    echo "Error: Invalid homepage URL. Must start with http:// or https://"
    exit 1
fi

# Process template
echo "Generating temporary XML file..."
sed -e "s|{CONFIG-NAME}|${CONFIG_NAME}|g" \
    -e "s|{PORT}|${PORT}|g" \
    -e "s|{IP}|${IP}|g" \
    -e "s|{APN}|${APN}|g" \
    -e "s|{HOMEPAGE}|${HOMEPAGE}|g" \
    template.xml > tmp.xml

# Convert to WBXML
echo "Converting to WBXML format..."
xml2wbxml -o "${CONFIG_NAME}.prov" tmp.xml

# Cleanup
rm -f tmp.xml

echo "Success: Provisioning file generated as '${CONFIG_NAME}.prov'"