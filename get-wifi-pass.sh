#!/bin/bash
echo "WiFi Passwords for your networks:"
echo "=================================="

for file in /etc/NetworkManager/system-connections/*; do
    if [ -f "$file" ]; then
        echo "Network: $(basename "$file")"
        echo "Password: $(sudo grep -oP 'psk=\K.*' "$file")"
        echo "------------------------"
    fi
done
