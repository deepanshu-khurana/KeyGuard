# Password Manager

A sleek, web-based cryptographic password manager built with Flask that allows users to securely generate, store, search, and rotate website credentials. Stored passwords are encrypted on-the-fly using AES-128 (Fernet) and monitored continuously against risk-exposure aging rules.


## About the Project

This project is a high-security, lightweight password vault engine designed to combine advanced cryptographic integrity with a modern, responsive interface. It features a stunning dark glassmorphism theme with customizable localized canvas backdrops and a robust background logic that enforces credential health management.


## Libraries and Technologies Used

The project relies on the following structural libraries:

- **Flask** – Core micro-framework handling stateful routing, controller workflows, and secure user sessions.

- **Flask-SQLAlchemy** – Object-Relational Mapper (ORM) managing transactional queries and SQLite schema integration.

- **bcrypt** – Advanced computational key-stretching function applied to hash and verify Master Passwords.

- **cryptography (Fernet)** – Industry-standard symmetric cipher algorithm executing authenticated AES-128 encryption.

- **Tailwind CSS** – Functional utility-first styling engine driving the glassmorphic ambient layout.

- **SQLite** – Embedded zero-configuration database layer ensuring ACID-compliant local persistent data storage.


## Functionalities

The application delivers a suite of secure password management operations:

- **Sleek Glassmorphic Dark UI**: Translucent component overlays styled with blur processing filters using custom graphical image assets.

- **Secure Master Authentication**: User accounts fortified with bcrypt salt-stretched hashing. Includes a quick toggle to preview input characters safely.

- **Isolated Cryptographic Key Chains**: Automatic instantiation of unique, separate AES vault keys for every individual user profile.

- **Password Generation Engine**: Instant calculation of cryptographically strong random strings constrained strictly between 10 and 20 ASCII characters using the secrets library.

- **Two-Way Vault Encryption**: Plaintext passwords are obfuscated via symmetric Fernet logic prior to disk compilation and decrypted exclusively in volatile memory space during UI rendering.

- **Secure Payload Queries**: Search queries rewritten from GET parameters to internal POST body buffers to wipe credentials completely from global browser history logs.

- **Flexible Chronological Entry Log**: Supports saving or updating accounts using the real-time server timestamp or selecting an exact historic calendar day.

- **Rolling Rotation Age Tracker**: Automatic calculations checking row histories against active datetimes to output granular lifespan indicators:

- **Secure (0–29 Days)**: Green badge confirming acceptable age.

- **At Risk (30–44 Days)**: Orange warning badge urging proactive configuration changes.

- **Expired / High Risk (45+ Days)**: Red warning badge highlighting critical exposure.

- **Inline Modifiers**: Dynamic form-switching layout allowing users to update existing account parameters and instantly reset rotation calendars without reloading the viewport.

- **Session Locking**: Single-click logout commands to purge context keys and secure the vault immediately.


## Project Structure

```text
password_manager/
│
├── venv/                       # Virtual environment (isolated dependencies)
├── vault.db                    # SQLite Database binary file (auto-generated)
├── app.py                      # Core entry point (Controllers, database configurations, and endpoints)
├── crypto_utils.py             # Security engine (entropy generation, master verification, AES blocks)
│
├── static/                     # Global front-end structural media assets
│   ├── login.png               # Centered layout backdrop for registration and landing pages
│   └── background.png          # High-resolution glass backdrop for the dashboard table matrix
│
└── templates/                  # Jinja2 layout templates
    ├── login.html              # Authenticated entrance interface with interactive show toggles
    ├── register.html           # Shield-aligned portal generating unique user profiles
    └── vault.html              # Centralized data ledger dashboard handling searches, additions, and updates
```


## How to Run the Project

1. Make sure Python 3.x is installed on your local environment.
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

The local SQLite relational database file (vault.db) will instantiate itself automatically in your folder architecture on the first page load.


## Security Architecture Notes

- *Data Privacy*: Master passwords are processed exclusively as unidirectional hashes; the plain text is never stored or logged anywhere on the host machine.

- *Key Separation*: Compromise of one user's database entry does not impact any other profile, as every vault row utilizes localized multi-tenant key boundaries.

- *Frontend Controls*: On-the-fly decryption patterns ensure your raw password arrays are never permanently stored inside the HTML document tree on the server side—they exist in plain text only within your active browser runtime instance.
