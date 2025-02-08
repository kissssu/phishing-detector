# Phishing Email Detector

This project implements a phishing email detection tool using Python with Flask for the backend and HTML, CSS, and JavaScript for the frontend.  It analyzes email content to identify potential phishing attempts and provides a probability score indicating the likelihood of an email being a scam.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)

## Introduction

Phishing emails are a significant security threat. This tool aims to help users identify potentially malicious emails by analyzing various factors, including sender address, subject line, body content, and links.  It provides a user-friendly interface to easily check emails and get a clear verdict.

## Features

* **Email Analysis:**  Examines email content for suspicious keywords, sender mismatches, generic greetings, and other red flags.
* **Probability Score:**  Calculates a probability score indicating the likelihood of an email being a phishing attempt.
* **User-Friendly Interface:**  Provides a simple and intuitive web interface for email analysis.
* **Detailed Results:** Displays a breakdown of the analysis, including identified suspicious elements.

## Installation

1. **Clone the repository:**
    ```
    git clone https://github.com/kissssu/phishing-email-detector.git
    cd phishing-email-detector
    ```
2. **Create a virtual environment** (recommended):
    ```
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3. Install dependencies:   
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. **Run the Flask application**:
    ```Bash
    python main.py  # Assuming main.py is your main script
    ```
2. **Open your web browser and navigate to ```http://127.0.0.1:5000``` (or the address shown in the terminal).**
3. **Paste the email content into the provided text area.**
4. **Click the "Analyze" button.**
5. **The results, including the verdict, probability score, and detailed analysis, will be displayed below.**

## Project Structure
```
phishing-email-detector/
├── analyzer.py     # Email analysis functions
├── main.py         # Flask application
├── README.md       # This file
├── Screenshots/    # Screenshots of the application
│   ├── phishing-detection-legit.png
│   └── phishing-detection-scan.png
├── static/         # CSS and JavaScript files
│   ├── script.js
│   └── styles.css
├── templates/      # HTML templates
│   └── index.html
└── texts/          # Sample emails (for testing)
    └── Sample-Emails.txt
```

## Future Enhancements

**UI/UX Improvements:**

*   Enhanced input (drag & drop, example email, validation).
*   Improved output (expandable sections, visual cues, detailed breakdown, tooltips, sharing, reports, feedback).
*   Modern styling and responsive design.

**Core Detection Enhancements:**

*   Robust link analysis.
*   In-depth HTML analysis.
*   Refined scoring algorithm.

**Advanced Features:**

*   Natural Language Processing (NLP) for content analysis.
*   AI/ML integration for improved accuracy and adaptive learning.

## Contributing

- Contributions are welcome!  Please open an issue or submit a pull request.

