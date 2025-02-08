# Planner.ai
(Forked)

Planner.ai is an intelligent study planning application built with Streamlit. It helps students create personalized study plans based on their course load, deadlines, and learning preferences, with enterprise-grade security features.

## Features
- Secure user registration and authentication with:
  - Password strength requirements
  - Email validation
  - Brute force protection
  - Account lockout system
- Encrypted data storage
- Secure session management
- Difficulty assessment quiz for Computer Science
- Personalized study plan generation using Cohere's AI
- Interactive course and deadline management
- Visualization of quiz results and study progress

## Security Features
- Password security:
  - bcrypt hashing with salt
  - Minimum 8 characters
  - Required uppercase and lowercase letters
  - Required numeric characters
- Rate limiting:
  - Account lockout after 5 failed attempts
  - 15-minute lockout period
- Data protection:
  - Email encryption using Fernet
  - Secure session tokens
  - Protected routes
- Database security:
  - WAL mode for concurrent access
  - Prepared statements to prevent SQL injection
  - Secure connection handling

## Technologies Used
- Python
- Streamlit
- SQLite
- Cohere API
- Matplotlib
- NumPy
- Pandas
- scikit-learn
- bcrypt
- cryptography
- secrets

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/planner-ai.git
   cd planner-ai
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up your Cohere API key:
   - Create a `.streamlit/secrets.toml` file in the project root
   - Add your Cohere API key to the file:
     ```
     [cohere]
     api_key = "your_cohere_api_key_here"
     ```

## Dependencies
Ensure your requirements.txt includes these security-related packages:
```
bcrypt>=4.0.1
cryptography>=41.0.0
```

## Usage
1. Run the Streamlit app:
   ```
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`).

3. Register for a new account:
   - Choose a username
   - Enter a valid email address
   - Create a strong password (8+ characters, upper/lowercase, numbers)

4. Log in securely to your account.

5. Complete the difficulty assessment quiz.

6. Add your courses and deadlines.

7. Input your study preferences.

8. Generate your personalized study plan.

## Security Best Practices
- Never share your login credentials
- Use a unique, strong password
- Don't attempt to bypass the rate limiting system
- Keep your API keys secure and never commit them to version control
- Regularly update your password
- Log out when finished, especially on shared computers

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request. When contributing, please:
- Follow secure coding practices
- Add tests for new security features
- Document security-related changes
- Never commit sensitive information

## Security Reporting
If you discover any security vulnerabilities, please report them via email instead of opening a public issue.

## Acknowledgments
- [Streamlit](https://streamlit.io/) for the awesome web app framework
- [Cohere](https://cohere.ai/) for providing the AI model for study plan generation
- [Open Trivia Database](https://opentdb.com/) for providing quiz questions
- [bcrypt](https://pypi.org/project/bcrypt/) for secure password hashing
- [cryptography](https://pypi.org/project/cryptography/) for data encryption
