#!/bin/bash
# script name: wifi_scanner.sh

INTERFACE="wlan0"
NETWORK="192.168.1.0/24"
OUTPUT_FILE="network_report_$(date +%Y%m%d_%H%M%S).txt"

echo "=== بدء فحص الشبكة ===" | tee $OUTPUT_FILE
echo "الوقت: $(date)" | tee -a $OUTPUT_FILE
echo "الشبكة: $NETWORK" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# 1. اكتشاف الأجهزة مع arp-scan
echo "=== الأجهزة المتصلة ===" | tee -a $OUTPUT_FILE
sudo arp-scan -I $INTERFACE --localnet | tee -a $OUTPUT_FILE

echo "" | tee -a $OUTPUT_FILE

# 2. مسح بالـ nmap
echo "=== تحليل الشبكة مع nmap ===" | tee -a $OUTPUT_FILE
sudo nmap -sS -sV -O $NETWORK | tee -a $OUTPUT_FILE

echo "" | tee -a $OUTPUT_FILE

# 3. التحقق من الثغرات الأساسية
echo "=== فحص الثغرات الأساسية ===" | tee -a $OUTPUT_FILE
sudo nmap --script vuln $NETWORK | tee -a $OUTPUT_FILE

echo "=== انتهى الفحص ===" | tee -a $OUTPUT_FILE
echo "النتائج محفوظة في: $OUTPUT_FILE"