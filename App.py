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
             background-image: url("https://images2.alphacoders.com/100/1006924.png");
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

# Function to generate study plan
def generate_study_plan(course_load, deadlines, preferences, quiz_results, api_key):
    prompt = f"Generate a detailed study plan for the following courses: {course_load}. " \
             f"The deadlines are: {deadlines}. The study preferences are: {preferences}. " \
             f"Based on the quiz results, the student's strength in Computer Science is: {quiz_results}."
    try:
        cohere_client = cohere.Client(api_key)
        response = cohere_client.generate(
            model='command-xlarge-nightly',
            prompt=prompt,
            max_tokens=1024,
            temperature=0.4
        )
        return response.generations[0].text
    except Exception as e:
        st.error(f"Error generating study plan: {e}")
        return None

# Function to get quiz questions from API
def get_quiz_questions():
    if 'quiz_questions' not in st.session_state:
        url = "https://opentdb.com/api.php?amount=30&category=18&difficulty=easy&type=multiple"
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            questions = data['results']
            
            for idx, question in enumerate(questions):
                question['id'] = str(idx)  # Ensure id is a string
                question['question'] = html.unescape(question['question'])
                options = question['incorrect_answers'] + [question['correct_answer']]
                options = [html.unescape(option) for option in options]
                np.random.shuffle(options)
                question['options'] = options
            
            st.session_state.quiz_questions = questions
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching quiz questions: {e}")
            return []
        except KeyError:
            st.error("Unexpected response format from API. Please check the API documentation.")
            return []
    
    return st.session_state.quiz_questions

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
    st.write('Answer the following questions to assess your strengths and weaknesses. You can choose not to answer a question.')

    questions = get_quiz_questions()

    if 'user_answers' not in st.session_state:
        st.session_state.user_answers = {}

    for question in questions:
        q_id = question['id']
        q_text = question['question']
        options = question['options'] + ['Skip']
        
        selected_option = st.radio(q_text, options, key=f"q_{q_id}")
        st.session_state.user_answers[q_id] = selected_option

    if st.button('Submit Quiz'):
        st.session_state.page = 'evaluate_quiz'
        st.experimental_rerun()

def evaluate_quiz():
    if not check_authentication():
        return
        
    st.header('📊 Assessment Results')
    st.write('Here are your results for the quiz:')

    subject_scores = {'Computers': 0}
    total_questions = {'Computers': 0}
    unanswered_count = 0

    for question in st.session_state.quiz_questions:
        q_id = question['id']
        correct_ans = question['correct_answer']
        user_ans = st.session_state.user_answers.get(q_id, "Skip")

        if user_ans == "Skip":
            unanswered_count += 1
            continue

        total_questions['Computers'] += 1

        if user_ans == correct_ans:
            subject_scores['Computers'] += 1

    total_computers_questions = total_questions['Computers']
    computers_score = (subject_scores['Computers'] / total_computers_questions) * 100 if total_computers_questions > 0 else 0
    st.session_state.computers_score = computers_score    
    
    # Display results
    fig1, ax1 = plt.subplots()
    ax1.bar(['Computers'], [computers_score])
    ax1.set_ylabel('Scores (%)')
    ax1.set_title('Quiz Assessment Results')
    ax1.set_ylim(0, 100)
    ax1.text(0, computers_score + 1, f"{computers_score:.2f}%", ha='center', va='bottom')
    st.pyplot(fig1)

    fig2, ax2 = plt.subplots()
    answered_count = total_computers_questions
    counts = [answered_count, unanswered_count]
    ax2.bar(['Answered', 'Unanswered'], counts)
    ax2.set_ylabel('Number of Questions')
    ax2.set_title('Answered vs Unanswered Questions')
    st.pyplot(fig2)

    st.write('*Strengths and Weaknesses*')
    st.write(f'Computers: {"Strong" if computers_score > 70 else "Weak"}')

    if st.button('Continue'):
        st.session_state.page = 'generate_study_plan'
        st.experimental_rerun()

# Application page
def app():
    if not check_authentication():
        return
        
    st.header('🗓️ Add Your Courses and Deadlines')

    if 'courses' not in st.session_state:
        st.session_state.courses = []

    def add_course():
        st.session_state.courses.append({'name': '', 'start_date': datetime.date.today(), 'end_date': datetime.date.today()})

    st.button('Add Course', on_click=add_course)

    for idx, course in enumerate(st.session_state.courses):
        with st.expander(f'Course {idx+1}'):
            name = st.text_input(f'Course Name {idx+1}', key=f'course_{idx}', value=course['name'])
            start_date = st.date_input(f'Start Date {idx+1}', key=f'start_date_{idx}', value=course['start_date'])
            end_date = st.date_input(f'End Date {idx+1}', key=f'end_date_{idx}', value=course['end_date'])
            st.session_state.courses[idx]['name'] = name
            st.session_state.courses[idx]['start_date'] = start_date
            st.session_state.courses[idx]['end_date'] = end_date

    st.header('📝 Input Your Study Preferences')
    preferences = st.text_area('Personal Preferences (e.g., study in the morning, prefer short sessions)', placeholder='Enter any study preferences')

    if st.button('Generate Study Plan'):
        if st.session_state.courses and preferences:
            course_load = [item['name'] for item in st.session_state.courses]
            deadlines_text = "; ".join([f"{item['name']} from {item['start_date']} to {item['end_date']}" for item in st.session_state.courses])
            quiz_results = "Strong" if st.session_state.get('computers_score', 0) > 70 else "Weak"
            study_plan = generate_study_plan(", ".join(course_load), deadlines_text, preferences, quiz_results, cohere_api_key)
            
            if study_plan:
                st.subheader('📅 Course Schedule')
                for course in st.session_state.courses:
                    st.write(f"{course['name']}: {course['start_date']} to {course['end_date']}")
                
                st.subheader('📝 Generated Study Plan')
                st.write(study_plan)
        else:
            st.error('Please fill in all the fields.')

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
