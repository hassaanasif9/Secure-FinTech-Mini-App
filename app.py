# app.py
# Secure FinTech mini-app for CY4053 assignment (Streamlit)
# Features: registration/login (bcrypt), password rules, input validation,
# session management, encrypted data storage (Fernet), audit logs, file upload validation.

from cryptography.fernet import Fernet
import sqlite3
import bcrypt
import streamlit as st
import re
import time
import os
import base64
import logging
from datetime import datetime, timedelta

# ----- CONFIG -----
DB_PATH = "fintech_secure.db"
KEY_PATH = "fernet.key"
SESSION_TIMEOUT_SECONDS = 300  # 5 minutes

# ----- LOGGING -----
logging.basicConfig(filename="app_errors.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# ----- HELPERS -----
def init_key():
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
    else:
        with open(KEY_PATH, "rb") as f:
            key = f.read()
    return key

FERNET = Fernet(init_key())

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # users: id, username (unique), password_hash, email, created_at
    c.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        email TEXT,
        created_at TEXT NOT NULL
    )''')
    # transactions: id, user_id, amount_encrypted, description_encrypted, created_at
    c.execute('''CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount BLOB,
        description BLOB,
        created_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    # audit logs
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    return conn

def log_action(user_id, action, details=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO audit_logs(user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, action, details, datetime.utcnow().isoformat()))
    conn.commit()

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password: str, pw_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), pw_hash)
    except Exception as e:
        logging.exception("Password verification error")
        return False

def validate_password_rules(pw: str) -> (bool, str):
    if len(pw) < 10:
        return False, "Password must be at least 10 characters."
    if not re.search(r"[0-9]", pw):
        return False, "Password must include a digit."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must include an uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Password must include a lowercase letter."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", pw):
        return False, "Password must include a special symbol."
    return True, "OK"

def sanitize_username(u: str) -> str:
    # allow letters, numbers, underscore, dot, dash
    return re.sub(r"[^A-Za-z0-9_.-]", "", u)

def encrypt_text(plaintext: str) -> bytes:
    return FERNET.encrypt(plaintext.encode('utf-8'))

def decrypt_text(ciphertext: bytes) -> str:
    return FERNET.decrypt(ciphertext).decode('utf-8')

def allowed_file(filename: str) -> bool:
    allowed_ext = {"png", "jpg", "jpeg", "pdf"}
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in allowed_ext

# ----- SESSION HELPERS -----
def is_logged_in():
    ss = st.session_state
    return ss.get("user_id") is not None

def require_login():
    if not is_logged_in():
        st.error("You must be logged in to access this page.")
        st.stop()

def set_session(user_id, username):
    ss = st.session_state
    ss["user_id"] = user_id
    ss["username"] = username
    ss["last_active"] = time.time()

def clear_session():
    for k in ["user_id", "username", "last_active"]:
        if k in st.session_state:
            del st.session_state[k]

def check_session_timeout():
    if is_logged_in():
        last = st.session_state.get("last_active", time.time())
        if time.time() - last > SESSION_TIMEOUT_SECONDS:
            user = st.session_state.get("user_id")
            clear_session()
            st.warning("Session timed out due to inactivity.")
            log_action(user, "session_timeout", "auto-logout due to inactivity")
            st.experimental_rerun()
        else:
            st.session_state["last_active"] = time.time()

# ----- UI -----
st.set_page_config(page_title="Secure FinTech Mini App", layout="centered")
conn = init_db()
st.title("Secure FinTech Mini App — CY4053 Assignment 2")

menu = ["Home", "Register", "Login", "Dashboard", "Logout"]
choice = st.sidebar.selectbox("Menu", menu)

# Home
if choice == "Home":
    st.write("""
    **Purpose:** small secure app showing authentication, validation, encryption, logging.
    Use **Register** to create account, then **Login** to access Dashboard.
    """)
    st.info("This app uses parameterized SQL, bcrypt password hashing, Fernet encryption for confidential fields, input validation, and audit logs.")

# Register
if choice == "Register":
    st.header("Create Account")
    uname = st.text_input("Username")
    email = st.text_input("Email")
    pw = st.text_input("Password", type="password")
    pw2 = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        uname_clean = sanitize_username(uname)
        if uname_clean != uname:
            st.warning("Username contained invalid characters; sanitized to: " + uname_clean)
            uname = uname_clean

        valid_pw, msg = validate_password_rules(pw)
        if not valid_pw:
            st.error(msg)
        elif pw != pw2:
            st.error("Passwords do not match.")
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.error("Invalid email format.")
        else:
            try:
                pw_hash = hash_password(pw)
                c = conn.cursor()
                c.execute("INSERT INTO users(username, password_hash, email, created_at) VALUES (?, ?, ?, ?)",
                          (uname, pw_hash, email, datetime.utcnow().isoformat()))
                conn.commit()
                st.success("Registration successful. Please login.")
                log_action(None, "register", f"username={uname}")
            except sqlite3.IntegrityError:
                st.error("Username already exists.")
            except Exception as e:
                logging.exception("Registration error")
                st.error("An error occurred. Please contact instructor.")

# Login
if choice == "Login":
    st.header("Login")
    lu = st.text_input("Username")
    lpw = st.text_input("Password", type="password")
    if st.button("Login"):
        try:
            c = conn.cursor()
            c.execute("SELECT id, password_hash FROM users WHERE username = ?", (lu,))
            row = c.fetchone()
            if row:
                user_id = row[0]
                pw_hash = row[1]
                if verify_password(lpw, pw_hash):
                    set_session(user_id, lu)
                    st.success("Login successful.")
                    log_action(user_id, "login", "user logged in")
                    st.experimental_rerun()
                else:
                    st.error("Invalid credentials.")
                    log_action(None, "failed_login", f"username={lu}")
            else:
                st.error("Invalid credentials.")
                log_action(None, "failed_login", f"username={lu}")
        except Exception:
            logging.exception("Login error")
            st.error("An error occurred during login.")

# Dashboard
if choice == "Dashboard":
    check_session_timeout()
    require_login()
    st.header(f"Dashboard — {st.session_state.get('username')}")
    user_id = st.session_state.get("user_id")

    # Profile update
    st.subheader("Profile")
    if st.checkbox("Show profile details"):
        c = conn.cursor()
        c.execute("SELECT username, email, created_at FROM users WHERE id = ?", (user_id,))
        r = c.fetchone()
        st.write({"username": r[0], "email": r[1], "created_at": r[2]})

    with st.form("update_profile"):
        st.write("Update Email")
        new_email = st.text_input("New Email")
        submitted = st.form_submit_button("Update")
        if submitted:
            if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                st.error("Invalid email.")
            else:
                c = conn.cursor()
                c.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
                conn.commit()
                st.success("Email updated.")
                log_action(user_id, "update_profile", f"new_email={new_email}")

    # Add a "transaction" (amount + description) — encrypted in DB
    st.subheader("Add Transaction")
    with st.form("tx_form"):
        amount = st.text_input("Amount (numeric)")
        desc = st.text_area("Description (max 300 chars)")
        submit_tx = st.form_submit_button("Add Transaction")
        if submit_tx:
            try:
                # validation
                if not re.match(r"^\d+(\.\d{1,2})?$", amount.strip()):
                    st.error("Amount must be numeric (optional 2 decimals).")
                elif len(desc) > 300:
                    st.error("Description too long.")
                else:
                    enc_amount = encrypt_text(amount.strip())
                    enc_desc = encrypt_text(desc.strip())
                    c = conn.cursor()
                    c.execute("INSERT INTO transactions(user_id, amount, description, created_at) VALUES (?, ?, ?, ?)",
                              (user_id, enc_amount, enc_desc, datetime.utcnow().isoformat()))
                    conn.commit()
                    st.success("Transaction stored securely.")
                    log_action(user_id, "add_transaction", f"len_desc={len(desc)}")
            except Exception:
                logging.exception("Add transaction error")
                st.error("Could not add transaction.")

    # Show decrypted transactions
    st.subheader("My Transactions")
    if st.checkbox("Show my transactions (decrypted)"):
        c = conn.cursor()
        c.execute("SELECT id, amount, description, created_at FROM transactions WHERE user_id = ?", (user_id,))
        rows = c.fetchall()
        tlist = []
        for r in rows:
            try:
                tlist.append({
                    "id": r[0],
                    "amount": decrypt_text(r[1]),
                    "description": decrypt_text(r[2]),
                    "created_at": r[3]
                })
            except Exception:
                tlist.append({"id": r[0], "amount": "[decryption error]", "description": "[decryption error]", "created_at": r[3]})
        st.write(tlist)

    # File upload (validate allowed types)
    st.subheader("Upload Supporting File (png/jpg/pdf)")
    uploaded = st.file_uploader("Upload file", type=["png", "jpg", "jpeg", "pdf"])
    if uploaded is not None:
        fname = uploaded.name
        if not allowed_file(fname):
            st.error("File type not allowed.")
            log_action(user_id, "file_upload_rejected", fname)
        else:
            # small file size check
            if uploaded.size > 2 * 1024 * 1024:
                st.error("File too large (max 2MB).")
                log_action(user_id, "file_upload_rejected_size", fname)
            else:
                save_path = os.path.join("uploads", f"{user_id}_{int(time.time())}_{fname}")
                os.makedirs("uploads", exist_ok=True)
                with open(save_path, "wb") as f:
                    f.write(uploaded.getbuffer())
                st.success("File uploaded and stored.")
                log_action(user_id, "file_upload", save_path)

    # View audit logs for this user (safe)
    st.subheader("Audit Logs (your actions)")
    if st.checkbox("Show my audit logs"):
        c = conn.cursor()
        c.execute("SELECT action, details, timestamp FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50",
                  (user_id,))
        logs = c.fetchall()
        st.write(logs)

    # Force an error (for testing controlled error handling)
    st.subheader("Testing - Controlled Error")
    if st.button("Force divide by zero (test)"):
        try:
            _ = 1 / 0
        except Exception:
            logging.exception("Controlled error triggered")
            st.error("An error occurred but was handled. Contact admin if persists.")
            log_action(user_id, "forced_error", "divide_by_zero_test")

# Logout
if choice == "Logout":
    if is_logged_in():
        uid = st.session_state.get("user_id")
        clear_session()
        st.success("Logged out.")
        log_action(uid, "logout", "user logged out")
    else:
        st.info("You are not logged in.")
