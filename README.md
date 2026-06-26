# Password Manager

A simple web-based password manager built with Flask that lets users register, log in, and securely store website credentials. Passwords are encrypted before being saved and can be viewed again when the user is logged in.

## About the Project

This project is a lightweight password vault application designed to demonstrate basic secure credential storage in a web app. It uses a local SQLite database and encryption to keep saved passwords protected.

## Libraries and Technologies Used

The project uses the following libraries:

- Flask - for building the web application and routes
- Flask-SQLAlchemy - for database models and SQLite integration
- bcrypt - for securely hashing master passwords
- cryptography - for encrypting and decrypting saved passwords
- SQLite - for local data storage

## Functionalities

The application provides the following features:

- User registration with a unique username
- Secure login using a master password
- Password hashing for master credentials
- Encryption of stored website passwords
- Saving credentials such as site name, URL, username/email, and password
- Viewing stored credentials inside the user vault
- Searching stored credentials by site name or username/email
- Generating a strong random password suggestion
- Logout to lock the vault

## Project Structure

- app.py - main Flask application and routes
- crypto_utils.py - password generation, hashing, and encryption/decryption helpers
- templates/ - HTML templates for login, registration, and vault pages
- static/ - static assets such as CSS and JavaScript
- vault.db - SQLite database created automatically when the app runs

## How to Run the Project

1. Make sure Python is installed on your system.
2. Install the required dependencies:

   ```bash
   pip install Flask Flask-SQLAlchemy bcrypt cryptography
   ```

3. Navigate to the project folder:

   ```bash
   cd Password-Manager
   ```

4. Start the application:

   ```bash
   python app.py
   ```

5. Open your browser and go to:

   ```text
   http://127.0.0.1:5000
   ```

The database will be created automatically on first run.

