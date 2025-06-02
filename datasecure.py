import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Initialize session state
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load and save functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Key & encryption helpers
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load stored data
stored_data = load_data()

# UI
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "StoreData", "RetrieveData"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to My Data Encryption System")
    st.markdown("""
    - Users store data with a unique passkey.
    - Users decrypt data by providing the correct passkey.
    - Multiple failed attempts result in lockout.
    - The system uses JSON for storage — no external databases!
    """)

elif choice == "Register":
    st.subheader("📝 Register a New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully!")
        else:
            st.error("Both fields are required")

elif choice == "Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data:
            if hash_password(password) == stored_data[username]["password"]:
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success("Login successful!")
            else:
                st.session_state.failed_attempts += 1
                st.error("Incorrect password")
        else:
            st.session_state.failed_attempts += 1
            st.error("User not found")

        if st.session_state.failed_attempts >= 3:
            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
            st.error(f"Too many failed attempts. Locked out for {LOCKOUT_DURATION} seconds.")

elif choice == "StoreData":
    st.subheader("💾 Store Encrypted Data")

    if st.session_state.authenticated_user is None:
        st.warning("You must log in first to store data.")
        st.stop()

    input_data = st.text_area("Enter data to encrypt and store")
    passkey = st.text_input("Enter encryption passkey", type="password")

    if st.button("Encrypt and Save"):
        if input_data and passkey:
            encrypted = encrypt_text(input_data, passkey)
            user = st.session_state.authenticated_user
            stored_data[user]["data"].append(encrypted)
            save_data(stored_data)
            st.success("Data encrypted and saved successfully.")
        else:
            st.error("Both data and passkey are required.")

elif choice == "RetrieveData":
    st.subheader("🔓 Retrieve and Decrypt Data")

    if st.session_state.authenticated_user is None:
        st.warning("You must log in first to retrieve data.")
        st.stop()

    passkey = st.text_input("Enter decryption passkey", type="password")
    user = st.session_state.authenticated_user

    if st.button("Decrypt My Data"):
        if passkey:
            decrypted_items = []
            for item in stored_data[user]["data"]:
                result = decrypt_text(item, passkey)
                if result:
                    decrypted_items.append(result)
                else:
                    decrypted_items.append("❌ Failed to decrypt (wrong key)")

            st.write("Your stored data:")
            for idx, entry in enumerate(decrypted_items, 1):
                st.markdown(f"**{idx}.** {entry}")
        else:
            st.error("Passkey is required.")
