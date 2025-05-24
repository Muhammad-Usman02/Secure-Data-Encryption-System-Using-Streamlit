import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet

# Constants
MASTER_PASSWORD = "admin123"
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Session State Initialization
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# Helper Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def increment_failed_attempts():
    st.session_state.failed_attempts += 1

# UI
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts! Please reauthorize.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            hashed_passkey = hash_passkey(passkey)
            stored_entry = st.session_state.stored_data.get(encrypted_text)

            if stored_entry and stored_entry["passkey"] == hashed_passkey:
                reset_failed_attempts()
                decrypted = decrypt_data(encrypted_text)
                st.success(f"✅ Decrypted Data: {decrypted}")
            else:
                increment_failed_attempts()
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            reset_failed_attempts()
            st.success("✅ Reauthorized successfully! Go to 'Retrieve Data' to try again.")
        else:
            st.error("❌ Incorrect password!")
