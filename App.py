import streamlit as st
import sqlite3
import html
import datetime
import pandas as pd
import cohere
import matplotlib.pyplot as plt
import numpy as np
import requests
from sklearn.preprocessing import LabelEncoder
import re
import bcrypt
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#bg image
def add_bg_from_url():
    st.markdown(
         f"""
         <style>
         .stApp {{
             background-image: url("https://getwallpapers.com/wallpaper/full/2/2/5/633544.jpg");
             background-attachment: fixed;
             background-size: cover;
             background-position: center;
         }}
         .stApp::before {{
             content: "";
             position: fixed;
             top: 0;
             left: 0;
             width: 100%;
             height: 100%;
             background-color: rgba(25, 25, 25, 0.4);
             z-index: -1;
         }}
         </style>
         """,
         unsafe_allow_html=True
    )

# Generate a secure key for session encryption
def generate_key():
    if 'encryption_key' not in st.session_state:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'static_salt',  # In production, use a proper salt management system
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secrets.token_bytes(32)))
        st.session_state.encryption_key = key
        st.session_state.cipher_suite = Fernet(key)

# Configuration for secrets
try:
    cohere_api_key = st.secrets["cohere"]["api_key"]
except KeyError as e:
    st.error(f"Missing secret: {e}. Please make sure your Streamlit secrets are configured correctly.")
    st.stop()

# Initialize Cohere client
cohere_client = cohere.Client(cohere_api_key)

# Function to create the users table with encrypted data
def create_users_table():
    conn = sqlite3.connect('users.db', check_same_thread=False)
    c = conn.cursor()
    
    # Enable WAL mode for better concurrency and durability
    c.execute('PRAGMA journal_mode=WAL')
    
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email_hash TEXT UNIQUE,
        password_hash TEXT,
        salt TEXT,
        failed_attempts INTEGER DEFAULT 0,
        last_attempt TIMESTAMP
    )""")
    
    conn.commit()
    conn.close()

# Function to hash password with salt
def hash_password(password, salt=None):
    if salt is None:
        salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt), salt

# Function to hash email
def hash_email(email, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(email.encode())

# Function to decrypt email
def decrypt_email(email_hash, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(email_hash).decode()

# Function to validate email
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

# Function to register a new user with enhanced security
def register_user(username, email, password):
    generate_key()
    conn = sqlite3.connect('users.db', check_same_thread=False)
    c = conn.cursor()
    
    try:
        # Check for existing username
        c.execute("SELECT username FROM users WHERE username=?", (username,))
        if c.fetchone():
            st.error("Username already exists. Please choose a different username.")
            return False
        
        # Hash and encrypt user data
        password_hash, salt = hash_password(password)
        email_hash = hash_email(email, st.session_state.encryption_key)
        
        # Store user with hashed and encrypted data
        c.execute("""
            INSERT INTO users (username, email_hash, password_hash, salt)
            VALUES (?, ?, ?, ?)
        """, (username, email_hash, password_hash, salt))
        
        conn.commit()
        st.success("Registration successful! You can now login.")
        return True
        
    except sqlite3.IntegrityError:
        st.error("An error occurred during registration. Please try again.")
        return False
    finally:
        conn.close()

# Function to authenticate user with rate limiting and secure comparison
def authenticate_user(username, password):
    generate_key()
    conn = sqlite3.connect('users.db', check_same_thread=False)
    c = conn.cursor()
    
    try:
        # Get user data and check for rate limiting
        c.execute("""
            SELECT password_hash, salt, failed_attempts, last_attempt 
            FROM users WHERE username=?
        """, (username,))
        result = c.fetchone()
        
        if not result:
            return False
            
        password_hash, salt, failed_attempts, last_attempt = result
        
        # Implement rate limiting
        if failed_attempts >= 5:
            if last_attempt:
                last_attempt = datetime.datetime.fromisoformat(last_attempt)
                if datetime.datetime.now() - last_attempt < datetime.timedelta(minutes=15):
                    st.error("Account temporarily locked. Please try again later.")
                    return False
                else:
                    # Reset failed attempts after lockout period
                    c.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
                    conn.commit()
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            # Reset failed attempts on successful login
            c.execute("""
                UPDATE users 
                SET failed_attempts=0, last_attempt=NULL 
                WHERE username=?
            """, (username,))
            conn.commit()
            return True
        else:
            # Increment failed attempts
            c.execute("""
                UPDATE users 
                SET failed_attempts=failed_attempts+1, 
                    last_attempt=? 
                WHERE username=?
            """, (datetime.datetime.now().isoformat(), username))
            conn.commit()
            return False
            
    except Exception as e:
        st.error("An error occurred during authentication. Please try again.")
        return False
    finally:
        conn.close()

# Function to create secure session
def create_session(username):
    session_token = secrets.token_urlsafe(32)
    st.session_state.session_token = session_token
    st.session_state.username = username
    st.session_state.logged_in = True
    return session_token

# Function to validate session
def validate_session():
    if not st.session_state.get('session_token'):
        return False
    return True

# Function to end session
def end_session():
    if 'session_token' in st.session_state:
        del st.session_state.session_token
    if 'username' in st.session_state:
        del st.session_state.username
    st.session_state.logged_in = False

# Initialize the app
def initialize():
    create_users_table()

# Initialize the app
initialize()

def register():
    st.title("Planner.ai - Register")
    
    if 'registration_success' not in st.session_state:
        st.session_state.registration_success = False

    if not st.session_state.registration_success:
        with st.form("register_form"):
            username = st.text_input("Username")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit_button = st.form_submit_button("Register")
            
            if submit_button:
                if not username or not email or not password:
                    st.error("All fields are required.")
                elif len(password) < 8:
                    st.error("Password must be at least 8 characters long.")
                elif not any(c.isupper() for c in password):
                    st.error("Password must contain at least one uppercase letter.")
                elif not any(c.islower() for c in password):
                    st.error("Password must contain at least one lowercase letter.")
                elif not any(c.isdigit() for c in password):
                    st.error("Password must contain at least one number.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                else:
                    if register_user(username, email, password):
                        st.session_state.registration_success = True
                        st.experimental_rerun()
                    else:
                        st.error("Registration failed. Please try again.")
    else:
        st.success("Registration successful! You can now login.")
        st.session_state.page = 'login'

# Login page with enhanced security
def login():
    st.title("📊Planner.ai - Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if authenticate_user(username, password):
                create_session(username)
                st.success("Login successful!")
                st.session_state.page = 'difficulty_assess'
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")

# Protected routes validation
def check_authentication():
    if not validate_session():
        st.session_state.page = 'login'
        st.error("Please login to access this page")
        st.experimental_rerun()
        return False
    return True

def difficulty_assess():
    if not check_authentication():
        return
        
    st.header('📊 Difficulty Assessment Quiz')
    # ... rest of your difficulty_assess function ...

def evaluate_quiz():
    if not check_authentication():
        return
        
    st.header('📊 Assessment Results')
    # ... rest of your evaluate_quiz function ...

def app():
    if not check_authentication():
        return
        
    st.header('🗓️ Add Your Courses and Deadlines')
    # ... rest of your app function ...

# Main app with secure routing
def main():
    add_bg_from_url()
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if 'page' not in st.session_state:
        st.session_state.page = 'login'
    
    # Sidebar for navigation and logout
    st.sidebar.title("Planner.ai")
    if st.session_state.logged_in and validate_session():
        st.sidebar.title(f"Welcome, {st.session_state.username}!")
        if st.sidebar.button('Logout'):
            end_session()
            st.session_state.page = 'login'
            st.experimental_rerun()
        
        if st.sidebar.button('Back'):
            if st.session_state.page == 'difficulty_assess':
                end_session()
                st.session_state.page = 'login'
            elif st.session_state.page == 'evaluate_quiz':
                st.session_state.page = 'difficulty_assess'
            elif st.session_state.page == 'generate_study_plan':
                st.session_state.page = 'evaluate_quiz'
            st.experimental_rerun()
        
        if st.session_state.page == 'difficulty_assess':
            difficulty_assess()
        elif st.session_state.page == 'evaluate_quiz':
            evaluate_quiz()
        elif st.session_state.page == 'generate_study_plan':
            app()
    else:
        page = st.sidebar.radio("Choose a page", ["Login", "Register"])
        if page == "Login":
            login()
        elif page == "Register":
            register()

if __name__ == "__main__":
    main()
