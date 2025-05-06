import sys
import argparse
import mysql.connector
import requests
from datetime import datetime
import hashlib
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import os
import traceback
import requests

# --- Configuration (Update these paths!) ---
LOG_DIR = "D:\\xampp\\HTTPS\\logs\\password-leak-scan"
LOCK_FILE = os.path.join(LOG_DIR, "password_leak_scan.lock")

DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "password_manager"
}

# --- Ensure log directory exists ---
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# --- Logging ---
def log_message(log_type, message):
    """Logs messages to error/debug files with timestamps."""
    log_date = datetime.now().strftime("%Y-%m-%d")
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if log_type == "error":
        log_file = os.path.join(LOG_DIR, f"error_{log_date}.log")
        level = "ERROR"
    else:
        log_file = os.path.join(LOG_DIR, f"debug_{log_date}.log")
        level = "DEBUG"
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(f"[{log_time}] [{level}] {message}\n")

def evp_bytes_to_key(password: bytes, key_len=32, iv_len=16):
    """Emulates OpenSSL EVP_BytesToKey derivation as used in PHP openssl_decrypt()"""
    d = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d + password).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]

def decrypt_password(encrypted_str, key_str):
    try:
        resp = requests.post("http://127.0.0.1:81/API/securePass_decrypt_password_api.php", json={
            "encrypted": encrypted_str,
            "key": key_str
        }, timeout=5)

        result = resp.json()
        if result.get("success"):
            return result.get("decrypted")
        else:
            log_message("error", f"PHP decryption failed: {result.get('error')}")
            return None
    except Exception as e:
        log_message("error", f"PHP decryption request error: {str(e)}")
        return None

# --- Lock file handling ---

def is_already_running():
    return os.path.exists(LOCK_FILE)

def create_lock():
    with open(LOCK_FILE, "w") as file:
        file.write(str(os.getpid()))

def remove_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

def sha1_hex(s):
    import hashlib
    return hashlib.sha1(s.encode('utf-8')).hexdigest().upper()

def check_pwned_password(password):
    try:
        hash = sha1_hex(password)
        prefix = hash[:5]
        suffix = hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            log_message("error", f"HIBP API error {r.status_code} for prefix {prefix}")
            return -1
        for line in r.text.splitlines():
            parts = line.strip().split(':')
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1])  # Number of times in breaches
        return 0
    except Exception as ex:
        log_message("error", f"Error in check_pwned_password: {ex}\n{traceback.format_exc()}")
        return -1

def update_leak_scan(unique_id, leak_count, requested_by_user):
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        cursor = db.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        flag = 1 if leak_count > 0 else 0
        cursor.execute("""
            INSERT INTO password_leak_scan (vault_unique_id, last_checked, leak_found, leak_count, requested_by_user)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                last_checked = VALUES(last_checked),
                leak_found = VALUES(leak_found),
                leak_count = VALUES(leak_count),
                requested_by_user = VALUES(requested_by_user)
        """, (unique_id, now, flag, leak_count if leak_count > 0 else 0, requested_by_user))
        db.commit()
        cursor.close()
        db.close()
        log_message("debug", f"Updated scan for {unique_id} (leak_count={leak_count}, requested_by_user={requested_by_user})")
    except Exception as ex:
        log_message("error", f"DB update error for {unique_id}: {ex}\n{traceback.format_exc()}")

def scan_by_unique_id(unique_id):
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        cursor = db.cursor()
        cursor.execute("""
        SELECT v.AppName, v.UserName, v.Password, e.EncryptionKey 
        FROM vault v 
        JOIN encryption e ON v.EncryptionKeyId = e.EncryptionKeyVersion 
        AND CONVERT(v.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci = CONVERT(e.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci 
        WHERE v.UniqueId=%s AND v.DeleteFlag=0 AND v.ActiveFlag=1
    """, (unique_id,))
        row = cursor.fetchone()
        cursor.close()
        db.close()
        if not row:
            log_message("error", f"No record for UniqueId={unique_id}")
            print("NO_RECORD")
            sys.exit(1)
        app_name, user_name, encrypted_password, encryption_key = row
        decrypted_password = decrypt_password(encrypted_password, encryption_key)
        if decrypted_password is None:
            log_message("error", f"Skipping scan for {unique_id} due to decryption failure")
            print(f"{unique_id}:{app_name}:{user_name}:ERROR")
            return
        password = decrypted_password
        leak_count = check_pwned_password(password)
        update_leak_scan(unique_id, leak_count, requested_by_user=1)
        if leak_count == -1:
            log_message("error", f"Scan error for {unique_id} ({app_name}/{user_name})")
            print(f"{unique_id}:{app_name}:{user_name}:ERROR")
        elif leak_count > 0:
            log_message("debug", f"Leak found for {unique_id} ({app_name}/{user_name}), leak_count={leak_count}")
            print(f"{unique_id}:{app_name}:{user_name}:LEAK_FOUND:{leak_count}")
        else:
            log_message("debug", f"No leak for {unique_id} ({app_name}/{user_name})")
            print(f"{unique_id}:{app_name}:{user_name}:NO_LEAK")
    except Exception as ex:
        log_message("error", f"Exception in scan_by_unique_id for {unique_id}: {ex}\n{traceback.format_exc()}")

def scan_by_useremailid(user_email_id):
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        cursor = db.cursor()
        cursor.execute("""
        SELECT v.UniqueId, v.AppName, v.UserName, v.Password, e.EncryptionKey 
        FROM vault v 
        JOIN encryption e ON v.EncryptionKeyId = e.EncryptionKeyVersion 
        AND CONVERT(v.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci = CONVERT(e.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci 
        WHERE CONVERT(v.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci = %s AND v.DeleteFlag=0 AND v.ActiveFlag=1
    """, (user_email_id,))
        rows = cursor.fetchall()
        cursor.close()
        db.close()
        if not rows:
            log_message("error", f"No records for UserEmailId={user_email_id}")
            print("NO_RECORDS")
            sys.exit(1)
        for unique_id, app_name, user_name, encrypted_password, encryption_key in rows:
            decrypted_password = decrypt_password(encrypted_password, encryption_key)
            if decrypted_password is None:
                log_message("error", f"Skipping scan for {unique_id} due to decryption failure")
                continue
            password = decrypted_password
            leak_count = check_pwned_password(password)
            update_leak_scan(unique_id, leak_count, requested_by_user=1)
            time.sleep(1)
            if leak_count == -1:
                log_message("error", f"Scan error for {unique_id} ({app_name}/{user_name})")
                print(f"{unique_id}:{app_name}:{user_name}:ERROR")
            elif leak_count > 0:
                log_message("debug", f"Leak found for {unique_id} ({app_name}/{user_name}), leak_count={leak_count}")
                print(f"{unique_id}:{app_name}:{user_name}:LEAK_FOUND:{leak_count}")
            else:
                log_message("debug", f"No leak for {unique_id} ({app_name}/{user_name})")
                print(f"{unique_id}:{app_name}:{user_name}:NO_LEAK")
    except Exception as ex:
        log_message("error", f"Exception in scan_by_useremailid for {user_email_id}: {ex}\n{traceback.format_exc()}")

def scan_all():
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        cursor = db.cursor()
        cursor.execute("""
        SELECT v.UniqueId, v.AppName, v.UserName, v.Password, e.EncryptionKey 
        FROM vault v 
        JOIN encryption e ON v.EncryptionKeyId = e.EncryptionKeyVersion 
        AND CONVERT(v.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci = CONVERT(e.UserEmailId USING utf8mb4) COLLATE utf8mb4_general_ci 
        WHERE v.DeleteFlag=0 AND v.ActiveFlag=1
    """)
        for unique_id, app_name, user_name, encrypted_password, encryption_key in cursor.fetchall():
            decrypted_password = decrypt_password(encrypted_password, encryption_key)
            if decrypted_password is None:
                log_message("error", f"Skipping scan for {unique_id} due to decryption failure")
                continue
            password = decrypted_password
            leak_count = check_pwned_password(password)
            update_leak_scan(unique_id, leak_count, requested_by_user=0)
            time.sleep(1)
            if leak_count == -1:
                log_message("error", f"Scan error for {unique_id} ({app_name}/{user_name})")
            elif leak_count > 0:
                log_message("debug", f"Leak found for {unique_id} ({app_name}/{user_name}), leak_count={leak_count}")
            else:
                log_message("debug", f"No leak for {unique_id} ({app_name}/{user_name})")
        cursor.close()
        db.close()
        log_message("debug", "Completed scheduled scan of all vault entries.")
    except Exception as ex:
        log_message("error", f"Exception in scan_all: {ex}\n{traceback.format_exc()}")

if __name__ == '__main__':
    # --- Lock file handling ---
    if is_already_running():
        log_message("error", "Service is already running. Exiting to prevent duplicate execution.")
        print("Lock file exists: another scan is running. Exiting.")
        sys.exit(0)
    create_lock()
    try:
        log_message("debug", "Started password_leak_scan.py")
        parser = argparse.ArgumentParser()
        parser.add_argument('--all', action='store_true', help='Scan all records')
        parser.add_argument('--one', type=str, help='Scan one UniqueId')
        parser.add_argument('--user', type=str, help='Scan all by UserEmailId')
        args = parser.parse_args()
        if args.all:
            scan_all()
        elif args.one:
            scan_by_unique_id(args.one)
        elif args.user:
            scan_by_useremailid(args.user)
        else:
            log_message("error", "Invalid usage: no valid argument.")
            print("Usage: --all | --one <UniqueId> | --user <UserEmailId>")
            sys.exit(1)
    except Exception as ex:
        log_message("error", f"Unhandled exception in main: {ex}\n{traceback.format_exc()}")
    finally:
        remove_lock()
        log_message("debug", "Finished password_leak_scan.py")
