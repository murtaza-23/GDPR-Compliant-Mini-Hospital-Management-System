import os
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from database import get_connection

KEY_FILE = "secret.key"

def load_or_create_key() -> bytes:
    # Loads the Fernet key from secret.key, or generates a new one if missing
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
        
    key = Fernet.generate_key()

    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

# Initialize global cipher suite
_cipher = Fernet(load_or_create_key())

def encrypt_data(plain_text: str) -> str:
    # Encrypts a UTF-8 string using Fernet and returns a base64 token string
    if not plain_text:
        return ""
    
    byte_text = str(plain_text).encode("utf-8")
    encrypted_text = _cipher.encrypt(byte_text)
    return encrypted_text.decode("utf-8")

def decrypt_data(cipher_text: str) -> str:
    # Decrypts a Fernet token string back to plain text safely
    if not cipher_text:
        return ""
    try:
        byte_text = str(cipher_text).encode("utf-8")
        decrypted_text = _cipher.decrypt(byte_text)
        return decrypted_text.decode("utf-8")

    except InvalidToken:
        return f"[DECRYPTION ERROR: Invalid Token]"
    except Exception as e:
        return f"[DECRYPTION ERROR: {e}]"

def mask_patient_data(patient_index: int, contact: str, diagnosis: str) -> tuple[str, str, str]:
    # Generates masked identifiers matching the assignment specification    
    anon_name = f"ANON_{1000 + patient_index}"  # e.g. Name -> ANON_1001
    digits = "".join(ch for ch in contact if ch.isdigit())
    last_four = digits[-4:] if len(digits) >= 4 else "0000"
    anon_contact = f"XXX-XXX-{last_four}"   # e.g. Contact -> XXX-XXX-4592
    anon_diagnosis = "[REDACTED - RESTRICTED]"

    return anon_name, anon_contact, anon_diagnosis

def _compute_log_hash(prev_hash: str, user_id: int, role: str, action: str, timestamp: str, details: str) -> str:
    # Computes a deterministic SHA-256 hash for a log entry
    payload = f"{prev_hash}|{user_id}|{role}|{action}|{timestamp}|{details}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def log_action(user_id: int, role: str, action: str, details: str = "") -> None:
    # Appends a hash-chained audit record into the logs table
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Fetch the entry_hash of the most recent log (or 'GENESIS' if table is empty)
        cursor.execute("SELECT entry_hash FROM logs ORDER BY log_id DESC LIMIT 1;")
        last_row = cursor.fetchone()
        prev_hash = last_row["entry_hash"] if last_row else "HOSPITAL_AUDIT_ROOT"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        entry_hash = _compute_log_hash(prev_hash, user_id, role, action, timestamp, details)

        cursor.execute("""
            INSERT INTO logs (user_id, role, action, timestamp, details, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (user_id, role, action, timestamp, details, prev_hash, entry_hash))

        conn.commit()

    except Exception as e:
        print(f"[Security Log Error] {e}")
    finally:
        if conn:
            conn.close()

def verify_log_integrity() -> tuple[bool, str]:
    # Walks through all rows in 'logs' and verifies the SHA-256 hash chain
    # Returns (True, message) if intact, or (False, error_message) if tampered

    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM logs ORDER BY log_id ASC;"
        cursor.execute(query)
        rows = cursor.fetchall()

        expected_prev = "HOSPITAL_AUDIT_ROOT"
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return False, f"Chain broken at Log ID {row['log_id']} (previous hash mismatch)."
            recalculated = _compute_log_hash(
                row["prev_hash"], row["user_id"], row["role"],
                row["action"], row["timestamp"], row["details"]
            )
            if row["entry_hash"] != recalculated:
                return False, f"Tampering detected at Log ID {row['log_id']} (data modified)."
            expected_prev = row["entry_hash"]

        return True, f"All {len(rows)} audit log entries verified intact."
    
    except Exception as e:
        return False, f"Verification error: {e}"
    
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    sample = "Murtaza Aamir"
    enc = encrypt_data(sample)
    dec = decrypt_data(enc)
    print(f"Original: {sample} | Encrypted: {enc[:25]}... | Decrypted: {dec}")