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
             background-color: rgba(25, 25, 25, 0.4);  # Adjust the last value (0.7) for transparency
             z-index: -1;
         }}
         </style>
         """,
         unsafe_allow_html=True
    )

# Configuration for secrets
try:
    cohere_api_key = st.secrets["cohere"]["api_key"]
except KeyError as e:
    st.error(f"Missing secret: {e}. Please make sure your Streamlit secrets are configured correctly.")
    st.stop()

# Initialize Cohere client
cohere_client = cohere.Client(cohere_api_key)

# Function to create the users table in the database
def create_users_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Check if the table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = c.fetchone()
    
    if not table_exists:
        # If the table doesn't exist, create it with all columns
        c.execute('''CREATE TABLE users
                     (username TEXT PRIMARY KEY, email TEXT UNIQUE, password TEXT)''')
    else:
        # If the table exists, check if the email column exists
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        
        if 'email' not in columns:
            # If email column doesn't exist, we need to recreate the table
            # First, rename the existing table
            c.execute("ALTER TABLE users RENAME TO users_old")
            
            # Create the new table with all columns
            c.execute('''CREATE TABLE users
                         (username TEXT PRIMARY KEY, email TEXT UNIQUE, password TEXT)''')
            
            # Copy data from the old table to the new table
            c.execute("INSERT INTO users (username, password) SELECT username, password FROM users_old")
            
            # Drop the old table
            c.execute("DROP TABLE users_old")
    
    conn.commit()
    conn.close()

# Function to register a new user
def register_user(username, email, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    if c.fetchone():
        st.error("Username already exists. Please choose a different username.")
        return False
    else:
        c.execute("SELECT email FROM users WHERE email=?", (email,))
        if c.fetchone():
            st.error("Email already registered. Please use a different email address.")
            return False
        else:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
            st.success("Registration successful! You can now login.")
            return True
    conn.close()

# Function to check if a user exists and if the password is correct
def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return password == result[0]
    else:
        return False

# Function to initialize the app
def initialize():
    create_users_table()

# Initialize the app
initialize()

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
            max_tokens=1500,
            temperature=0.4
        )
        return response.generations[0].text
    except Exception as e:
        st.error(f"Error generating study plan: {e}")
        return None

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

# Function to validate email
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None
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
        

# Login page
def login():
    st.title("📊Planner.ai - Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if authenticate_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.page = 'difficulty_assess'
                st.success("Login successful!")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")

def difficulty_assess():
    st.header('📊 Difficulty Assessment Quiz')
    st.write('Answer the following questions to assess your strengths and weaknesses. You can choose not to answer a question.')

    questions = get_quiz_questions()

    if 'user_answers' not in st.session_state:
        st.session_state.user_answers = {}

    for idx, question in enumerate(questions):
        q_id = question['id']
        q_text = question['question']
        options = question['options'] + ['Skip']
        
        st.subheader(f"Question {idx + 1}")
        selected_option = st.radio(q_text, options, key=f"q_{q_id}")
        st.session_state.user_answers[q_id] = selected_option

    if st.button('Submit Quiz'):
        st.session_state.page = 'evaluate_quiz'
        st.experimental_rerun()


def evaluate_quiz():
    st.header('📊 Assessment Results')
    st.write('Here are your results for the quiz:')

    subject_scores = {'Computers': 0}
    total_questions = {'Computers': 0}
    unanswered_count = 0
    correct_count = 0
    wrong_count = 0

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
            correct_count += 1
        else:
            wrong_count += 1

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

    # New graph for correct and wrong answers
    fig3, ax3 = plt.subplots()
    labels = ['Correct', 'Wrong']
    sizes = [correct_count, wrong_count]
    colors = ['green', 'red']
    ax3.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax3.axis('equal')
    ax3.set_title('Correct vs Wrong Answers')
    st.pyplot(fig3)

    st.write('**Strengths and Weaknesses**')
    st.write(f'Computers: {"Strong" if computers_score > 70 else "Weak"}')

    st.write('**Performance**')
    st.write(f'Correct Answers: {correct_count}')
    st.write(f'Wrong Answers: {wrong_count}')
    st.write(f'Unanswered Questions: {unanswered_count}')

    if st.button('Continue'):
        st.session_state.page = 'generate_study_plan'
        st.experimental_rerun()

# Application page
def app():
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


# Main app
def main():
    add_bg_from_url()
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if 'page' not in st.session_state:
        st.session_state.page = 'login'
    
    # Sidebar for navigation and logout
    st.sidebar.title("Planner.ai")
    if st.session_state.logged_in:
        st.sidebar.title(f"Welcome, {st.session_state.username}!")
        if st.sidebar.button('Logout'):
            st.session_state.logged_in = False
            st.session_state.page = 'login'
            st.experimental_rerun()
        
        if st.sidebar.button('Back'):
            if st.session_state.page == 'difficulty_assess':
                st.session_state.page = 'login'
                st.session_state.logged_in = False
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
