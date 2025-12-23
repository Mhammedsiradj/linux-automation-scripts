#!/usr/bin/env python3
"""
أداة تحليل وفك تشفير متعددة الطرق
مخصصة للتحديات الأمنية والتعليمية فقط
"""

import base64
import binascii
import codecs
import re
import hashlib
import string
from Crypto.Cipher import AES, DES
import argparse
import os

def detect_encoding(data):
    """الكشف عن نوع التشفير/الترميز"""
    encodings = []
    
    # Base64
    try:
        if re.match(r'^[A-Za-z0-9+/]+=*$', data):
            decoded = base64.b64decode(data)
            if all(chr(b) in string.printable for b in decoded[:100]):
                encodings.append(('Base64', decoded.decode('utf-8', errors='ignore')))
    except:
        pass
    
    # Hex
    try:
        if re.match(r'^[0-9A-Fa-f]+$', data):
            decoded = bytes.fromhex(data)
            if all(chr(b) in string.printable for b in decoded[:100]):
                encodings.append(('Hex', decoded.decode('utf-8', errors='ignore')))
    except:
        pass
    
    # ROT13
    try:
        decoded = codecs.decode(data, 'rot_13')
        if any(c.isalpha() for c in decoded):
            encodings.append(('ROT13', decoded))
    except:
        pass
    
    # Base32
    try:
        decoded = base64.b32decode(data)
        if all(chr(b) in string.printable for b in decoded[:100]):
            encodings.append(('Base32', decoded.decode('utf-8', errors='ignore')))
    except:
        pass
    
    # URL Encoding
    try:
        import urllib.parse
        decoded = urllib.parse.unquote(data)
        if '%' in data and decoded != data:
            encodings.append(('URL Encoding', decoded))
    except:
        pass
    
    # Binary
    try:
        if re.match(r'^[01\s]+$', data.replace(' ', '')):
            binary_str = data.replace(' ', '')
            decoded = ''.join(chr(int(binary_str[i:i+8], 2)) 
                            for i in range(0, min(len(binary_str), 8*100), 8))
            encodings.append(('Binary', decoded))
    except:
        pass
    
    # Morse Code (بسيط)
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
        '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
        '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
        '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1',
        '..---': '2', '...--': '3', '....-': '4', '.....': '5',
        '-....': '6', '--...': '7', '---..': '8', '----.': '9'
    }
    
    morse_chars = data.replace(' ', '/').split('/')
    if all(c in '.-/ ' for c in data) and len(morse_chars) > 3:
        try:
            decoded = ''.join(morse_dict.get(c, ' ') for c in morse_chars)
            encodings.append(('Morse Code', decoded))
        except:
            pass
    
    # Caesar Cipher (جميع الإزاحات)
    if data.isalpha():
        for shift in range(1, 26):
            decoded = ''
            for char in data:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    decoded += chr((ord(char) - base - shift) % 26 + base)
                else:
                    decoded += char
            # تحقق إذا كانت النتيجة تحتوي على كلمات إنجليزية شائعة
            common_words = ['THE', 'AND', 'FOR', 'YOU', 'HAVE', 'THAT']
            if any(word in decoded.upper() for word in common_words):
                encodings.append((f'Caesar Cipher (shift={shift})', decoded))
    
    return encodings

def try_hash_identification(data):
    """التعرف على أنواع الهاش"""
    hash_lengths = {
        32: 'MD5',
        40: 'SHA1',
        56: 'SHA224',
        64: 'SHA256',
        96: 'SHA384',
        128: 'SHA512'
    }
    
    clean_data = data.strip().lower()
    length = len(clean_data)
    
    if length in hash_lengths:
        return f"ممكن يكون {hash_lengths[length]} hash"
    
    if re.match(r'^\$[0-9a-z]+\$[a-z0-9./]+$', data):
        return "ممكن يكون Unix crypt hash"
    
    return None

def analyze_file(filename):
    """تحليل ملف"""
    if not os.path.exists(filename):
        return "الملف غير موجود!"
    
    with open(filename, 'rb') as f:
        raw_data = f.read()
    
    # تحليل البيانات الأولية
    print(f"\n{'='*60}")
    print(f"تحليل الملف: {filename}")
    print(f"{'='*60}")
    print(f"الحجم: {len(raw_data)} بايت")
    
    # محاولة كـ نص
    try:
        data = raw_data.decode('utf-8')
        print(f"\n✅ يمكن قراءته كنص UTF-8")
        main_analysis(data)
    except:
        print(f"\n❌ لا يمكن قراءته كنص - ربما ملف ثنائي")
        
        # تحليل الهيدر
        hex_data = binascii.hexlify(raw_data[:100]).decode()
        print(f"الهيدر (hex): {hex_data[:50]}...")
        
        # فحص أنواع الملفات الشائعة
        if raw_data.startswith(b'PK'):
            print("📦 نوع الملف: ZIP Archive")
        elif raw_data.startswith(b'%PDF'):
            print("📄 نوع الملف: PDF Document")
        elif raw_data.startswith(b'\x89PNG'):
            print("🖼️  نوع الملف: PNG Image")

def main_analysis(data):
    """التحليل الرئيسي"""
    print(f"\n📊 طول البيانات: {len(data)} حرف")
    
    # إحصائيات
    letters = sum(c.isalpha() for c in data)
    digits = sum(c.isdigit() for c in data)
    special = sum(not c.isalnum() and not c.isspace() for c in data)
    
    print(f"📈 إحصائيات: {letters} حرف، {digits} رقم، {special} رمز خاص")
    
    # التعرف على الهاش
    hash_info = try_hash_identification(data)
    if hash_info:
        print(f"🔑 {hash_info}")
    
    # كشف الترميزات المختلفة
    print(f"\n🔍 جاري فحص الترميزات...")
    encodings = detect_encoding(data)
    
    if encodings:
        print(f"✅ تم العثور على {len(encodings)} ترميز محتمل:")
        for name, decoded in encodings[:5]:  # عرض أول 5 فقط
            print(f"\n📖 {name}:")
            print(f"   {decoded[:100]}{'...' if len(decoded) > 100 else ''}")
    else:
        print(f"❌ لم يتم التعرف على ترميز معروف")
    
    # بحث عن أنماط
    print(f"\n🎯 البحث عن أنماط:")
    
    # بحث عن أعلام CTF
    ctf_patterns = [
        r'FLAG\{[^}]+}', r'flag\{[^}]+}', 
        r'THM\{[^}]+}', r'HTB\{[^}]+}',
        r'picoCTF\{[^}]+}', r'cyber\{\w+\}'
    ]
    
    for pattern in ctf_patterns:
        matches = re.findall(pattern, data, re.IGNORECASE)
        for match in matches:
            print(f"   🚩 وجدت flag: {match}")
    
    # بحث عن روابط
    urls = re.findall(r'https?://[^\s]+', data)
    if urls:
        print(f"\n🌐 روابط وجدت: {len(urls)}")
        for url in urls[:3]:
            print(f"   🔗 {url}")
    
    # بحث عن إيميلات
    emails = re.findall(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', data)
    if emails:
        print(f"\n📧 إيميلات وجدت: {len(emails)}")
        for email in emails[:3]:
            print(f"   📨 {email}")

def interactive_mode():
    """الوضع التفاعلي"""
    print("🔓 أداة فك التشفير الذكية")
    print("=" * 40)
    
    while True:
        print("\n1. فحص نص")
        print("2. فحص ملف")
        print("3. فك Base64")
        print("4. فك Hex")
        print("5. فك ROT13")
        print("6. جميع تحويلات Caesar")
        print("7. خروج")
        
        choice = input("\nاختر خياراً [1-7]: ").strip()
        
        if choice == '1':
            text = input("أدخل النص: ").strip()
            main_analysis(text)
        
        elif choice == '2':
            filename = input("أدخل اسم الملف: ").strip()
            analyze_file(filename)
        
        elif choice == '3':
            text = input("أدخل نص Base64: ").strip()
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                print(f"✅ النتيجة: {decoded[:200]}")
            except:
                print("❌ ليس Base64 صالح")
        
        elif choice == '4':
            text = input("أدخل نص Hex: ").strip()
            try:
                decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
                print(f"✅ النتيجة: {decoded[:200]}")
            except:
                print("❌ ليس Hex صالح")
        
        elif choice == '5':
            text = input("أدخل نص ROT13: ").strip()
            decoded = codecs.decode(text, 'rot_13')
            print(f"✅ النتيجة: {decoded}")
        
        elif choice == '6':
            text = input("أدخل نص Caesar: ").strip()
            if text.isalpha():
                print("\nجميع الإزاحات الممكنة:")
                for shift in range(26):
                    decoded = ''
                    for char in text:
                        if char.isalpha():
                            base = ord('A') if char.isupper() else ord('a')
                            decoded += chr((ord(char) - base - shift) % 26 + base)
                        else:
                            decoded += char
                    print(f"Shift {shift:2}: {decoded}")
        
        elif choice == '7':
            print("مع السلامة!")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='أداة فك تشفير ذكية')
    parser.add_argument('-f', '--file', help='فحص ملف')
    parser.add_argument('-t', '--text', help='فحص نص')
    parser.add_argument('-i', '--interactive', action='store_true', help='الوضع التفاعلي')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode()
    elif args.file:
        analyze_file(args.file)
    elif args.text:
        main_analysis(args.text)
    else:
        parser.print_help()
        print("\nمثال:")
        print("  python decrypt_tool.py -t 'SGVsbG8gV29ybGQh'")
        print("  python decrypt_tool.py -f secret.txt")
        print("  python decrypt_tool.py -i")
