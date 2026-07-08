import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime

# Import the centralized security functions from crypto_utils.py
from crypto_utils import (
    generate_pass,
    hash_master_password,
    verify_master_password,
    encrypt_password,
    decrypt_password,
    generate_encryption_key
)

app = Flask(__name__)

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'super-secret-vault-key-12345')

# Configure local SQLite database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "vault.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------------------------------------------------
# DATABASE MODELS
# ---------------------------------------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    master_password_hash = db.Column(db.String(128), nullable=False)
    vault_key = db.Column(db.String(100), nullable=False)
    credentials = db.relationship('Credential', backref='owner', lazy=True)

class Credential(db.Model):
    __tablename__ = 'credentials'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    site_name = db.Column(db.String(100), nullable=False)
    site_url = db.Column(db.String(200))
    username_or_email = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.Date, nullable=False, default=datetime.utcnow)

# ---------------------------------------------------------
# CONTROLLERS & ROUTES
# ---------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        master_pwd = request.form.get('master_password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
            
        hashed_master = hash_master_password(master_pwd)
        user_vault_key = generate_encryption_key().decode('utf-8')
        
        new_user = User(username=username, master_password_hash=hashed_master, vault_key=user_vault_key)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('index'))
        
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username').strip()
    master_pwd = request.form.get('master_password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and verify_master_password(master_pwd, user.master_password_hash):
        session['user_id'] = user.id
        session['username'] = user.username
        session['vault_key'] = user.vault_key
        flash('Successfully logged into vault.', 'success')
        return redirect(url_for('vault'))
    else:
        flash('Invalid master credentials.', 'danger')
        return redirect(url_for('index'))

@app.route('/vault', methods=['GET', 'POST'])
def vault():
    if 'user_id' not in session:
        return redirect(url_for('index'))
        
    user_id = session['user_id']
    vault_key_bytes = session['vault_key'].encode('utf-8')
    
    search_query = ""
    if request.method == 'POST':
        search_query = request.form.get('search', '').strip()
        
    if search_query:
        credentials_query = Credential.query.filter(
            Credential.user_id == user_id,
            (Credential.site_name.contains(search_query)) | 
            (Credential.username_or_email.contains(search_query))
        ).all()
    else:
        credentials_query = Credential.query.filter_by(user_id=user_id).all()
        
    current_date = datetime.utcnow().date()
    decrypted_vault = []
    
    for cred in credentials_query:
        days_old = (current_date - cred.created_at).days
        if days_old < 0:
            days_old = 0
            
        decrypted_vault.append({
            'id': cred.id,
            'site_name': cred.site_name,
            'site_url': cred.site_url,
            'username_or_email': cred.username_or_email,
            'password': decrypt_password(cred.encrypted_password, vault_key_bytes),
            'days_old': days_old,
            'created_date_str': cred.created_at.strftime('%Y-%m-%d')
        })
        
    suggested_password = generate_pass()
    return render_template('vault.html', vault=decrypted_vault, suggested_password=suggested_password, search_query=search_query)

@app.route('/vault/add', methods=['POST'])
def add_credential():
    if 'user_id' not in session:
        return redirect(url_for('index'))
        
    site_name = request.form.get('site_name').strip()
    site_url = request.form.get('site_url').strip()
    username_or_email = request.form.get('username_or_email').strip()
    plain_password = request.form.get('password')
    
    date_mode = request.form.get('date_mode')
    if date_mode == 'custom':
        custom_date_str = request.form.get('custom_date')
        try:
            created_date = datetime.strptime(custom_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            created_date = datetime.utcnow().date()
    else:
        created_date = datetime.utcnow().date()
    
    vault_key_bytes = session['vault_key'].encode('utf-8')
    encrypted_pwd = encrypt_password(plain_password, vault_key_bytes)
    
    new_cred = Credential(
        user_id=session['user_id'],
        site_name=site_name,
        site_url=site_url,
        username_or_email=username_or_email,
        encrypted_password=encrypted_pwd,
        created_at=created_date
    )
    db.session.add(new_cred)
    db.session.commit()
    
    flash('Credential safely saved!', 'success')
    return redirect(url_for('vault'))

# NEW ROUTE: Processes secure modifications on targeted database records
@app.route('/vault/update/<int:cred_id>', methods=['POST'])
def update_credential(cred_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
        
    cred = Credential.query.filter_by(id=cred_id, user_id=session['user_id']).first_or_404()
    
    cred.site_name = request.form.get('site_name').strip()
    cred.site_url = request.form.get('site_url').strip()
    cred.username_or_email = request.form.get('username_or_email').strip()
    
    plain_password = request.form.get('password')
    vault_key_bytes = session['vault_key'].encode('utf-8')
    cred.encrypted_password = encrypt_password(plain_password, vault_key_bytes)
    
    date_mode = request.form.get('date_mode')
    if date_mode == 'custom':
        custom_date_str = request.form.get('custom_date')
        try:
            cred.created_at = datetime.strptime(custom_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            cred.created_at = datetime.utcnow().date()
    else:
        cred.created_at = datetime.utcnow().date()
        
    db.session.commit()
    flash('Record updated securely!', 'success')
    return redirect(url_for('vault'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Vault locked.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
