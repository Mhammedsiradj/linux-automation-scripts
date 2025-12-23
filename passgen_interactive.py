#!/usr/bin/env python3
import secrets
import string

def build_charset():
    # الحروف والأرقام والرموز
    charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?"
    return charset

def generate_password(length, charset):
    return ''.join(secrets.choice(charset) for _ in range(length))

def main():
    try:
        # طلب الطول
        length = int(input("🔑 أدخل طول كلمة المرور: "))
        # طلب عدد كلمات المرور
        number = int(input("📌 كم عدد كلمات المرور التي تريد إنشاءها؟ "))

        charset = build_charset()

        print("\n✅ تم إنشاء كلمات المرور:")
        for i in range(number):
            print(f"{i+1}: {generate_password(length, charset)}")

    except ValueError:
        print("⚠️ الرجاء إدخال أرقام صحيحة.")

if __name__ == "__main__":
    main()

