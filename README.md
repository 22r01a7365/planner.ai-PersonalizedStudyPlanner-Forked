# Planner.ai
(Forked)
Planner.ai is an intelligent study planning application built with Streamlit. It helps students create personalized study plans based on their course load, deadlines, and learning preferences.

## Features

- User registration and authentication
- Difficulty assessment quiz for Computer Science
- Personalized study plan generation using Cohere's AI
- Interactive course and deadline management
- Visualization of quiz results and study progress

## Technologies Used

- Python
- Streamlit
- SQLite
- Cohere API
- Matplotlib
- NumPy
- Pandas
- scikit-learn

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

## Usage

1. Run the Streamlit app:
   ```
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`).

3. Register for a new account or log in if you already have one.

4. Complete the difficulty assessment quiz.

5. Add your courses and deadlines.

6. Input your study preferences.

7. Generate your personalized study plan.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


## Acknowledgments

- [Streamlit](https://streamlit.io/) for the awesome web app framework
- [Cohere](https://cohere.ai/) for providing the AI model for study plan generation
- [Open Trivia Database](https://opentdb.com/) for providing quiz questions
