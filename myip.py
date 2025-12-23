#!/usr/bin/env python3
import socket
import os
import requests

def get_local_ip():
    """إيجاد الآي بي الداخلي"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # ما يحتاج يكون شغال فعلاً
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "غير معروف"
    finally:
        s.close()
    return ip

def get_gateway_ip():
    """إيجاد الآي بي الخاص بالراوتر (Gateway)"""
    try:
        with os.popen("ip route | grep default") as f:
            gateway = f.read().split()[2]
    except Exception:
        gateway = "غير معروف"
    return gateway

def get_public_ip():
    """إيجاد الآي بي الخارجي"""
    try:
        ip = requests.get("https://api.ipify.org").text
    except Exception:
        ip = "غير معروف"
    return ip

if __name__ == "__main__":
    print("📍 IP الداخلي (جهازك):", get_local_ip())
    print("📡 IP الراوتر (Gateway):", get_gateway_ip())
    print("🌍 IP الخارجي (Public):", get_public_ip())
