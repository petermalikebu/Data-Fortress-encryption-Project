import json
import csv
from hashlib import sha256
from flask import Response
from flask import Flask, render_template, make_response, request, redirect, url_for, session, flash, send_file
from flask_pymongo import PyMongo
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import qrcode
import os
import base64
from PIL import Image
import smtplib
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp  # For TOTP-based MFA
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from io import BytesIO
import threading
import schedule
import time
from functools import wraps
from datetime import datetime, timedelta, timezone 

# Define the requires_role decorator
def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if the user is logged in and has the required role
            if 'user_role' not in session or session['user_role'] != role:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('login'))  # Redirect to login or another appropriate page
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# MongoDB connection URI
mongo_uri = "mongodb://Database:admin@hostname:27017/admin"
client = MongoClient(mongo_uri)
db = client['database_name']

# AES Key and RSA Key Initialization (global scope to allow rotation)
aes_key = AESGCM.generate_key(bit_length=256)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Utility functions
def derive_key(password, salt):
    """Derives AES key from password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_data, aes_key):
    """Encrypts file data using AES-256-GCM."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return nonce, ciphertext

def decrypt_file(nonce, ciphertext, aes_key):
    """Decrypts file data using AES-256-GCM."""
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def wrap_aes_key(aes_key, public_key):
    """Wraps AES key using RSA public key."""
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key

def unwrap_aes_key(wrapped_key, private_key):
    """Unwraps AES key using RSA private key."""
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Key rotation function
def rotate_keys():
    global aes_key, private_key, public_key
    print("Rotating keys...")

    # Rotate AES key
    aes_key = AESGCM.generate_key(bit_length=256)

    # Rotate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    print("Keys rotated successfully")

# Schedule the key rotation every 12 hours
schedule.every(12).hours.do(rotate_keys)

def log_audit(action, user, details):
    """Logs an audit entry for the given action."""
    mongo.db.audit_logs.insert_one({
        "timestamp": datetime.utcnow(),
        "action": action,
        "user": user,
        "details": details
    })

# Flask app configuration
app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/Database'
mongo = PyMongo(app)

@app.route('/')
@app.route('/index')
def index():
    if 'email' in session:
        if session.get('user_role') == 'admin':
            return render_template('index.html', admin=True)
        else:
            return render_template('index.html', admin=False)
    else:
        flash("You need to log in first.")
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        role = request.form.get('role', 'user')  # Default to 'user' if not provided
        
        existing_user = mongo.db.users.find_one({'email': email})

        if existing_user:
            flash("User already exists.")
            return redirect(url_for('signup'))

        # If trying to sign up as admin, check the number of existing admins
        if role == 'admin':
            admin_count = mongo.db.users.count_documents({'role': 'admin'})
            if admin_count >= 2:
                flash("Maximum number of admin accounts reached. Cannot create more admins.")
                return redirect(url_for('signup'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Generate a new MFA secret for the user
        mfa_secret = pyotp.random_base32()

        # Insert user into the database with the mfa_secret
        mongo.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'phone': phone,
            'role': role,  # Assign the role during signup
            'verified': False,  # Default to False until MFA setup is completed
            'mfa_attempts': 0,  # Initialize MFA attempts
            'account_locked': False,  # Initialize account lock status
            'mfa_secret': mfa_secret  # Store the MFA secret
        })
        
          # Log the audit for user signup
        log_audit('User Signup', email, 'User signed up with phone number: ' + phone)

        flash("Signup successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user:
            if user.get('account_locked', False):
                flash("Account is locked. Contact support.")
                return redirect(url_for('login'))

            if check_password_hash(user['password'], password):
                # Successful password check, check if MFA is needed
                if not user['verified']:  # MFA is needed
                    session['login_email'] = email
                    return redirect(url_for('mfa_setup'))  # Redirect to MFA setup
                else:
                    session['email'] = email
                    session['user_role'] = user.get('role', 'user')
                    return redirect(url_for('dashboard'))  # Redirect to dashboard
            else:
                flash("Invalid credentials.")
                return redirect(url_for('login'))
        else:
            flash("User does not exist.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/mfa_setup', methods=['GET', 'POST'])
def mfa_setup():
    if 'login_email' not in session:
        return redirect(url_for('login'))

    email = session['login_email']
    user = mongo.db.users.find_one({'email': email})

    if request.method == 'POST':
        mfa_code = request.form.get('mfa_code', '')
        totp = pyotp.TOTP(user['mfa_secret'])
        
        if totp.verify(mfa_code):
            # MFA code is correct
            session['email'] = email
            session['user_role'] = user.get('role', 'user')

            # Mark the user as verified after successful MFA
            mongo.db.users.update_one({'email': email}, {'$set': {'verified': True}})
            return redirect(url_for('dashboard'))  # Redirect to dashboard

        else:
            # Increment MFA attempts on failure
            mongo.db.users.update_one(
                {'email': email},
                {'$inc': {'mfa_attempts': 1}}
            )
            user = mongo.db.users.find_one({'email': email})

            if user['mfa_attempts'] >= 5:
                mongo.db.users.update_one(
                    {'email': email},
                    {'$set': {'account_locked': True}}
                )
                flash("Account is locked due to too many failed MFA attempts.")
                return redirect(url_for('login'))
            else:
                flash("Invalid MFA code. Please try again.")
                return redirect(url_for('mfa_setup'))

    totp = pyotp.TOTP(user['mfa_secret'])
    qr_url = totp.provisioning_uri(name=email, issuer_name="SecureFile")

    qr = qrcode.make(qr_url)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_image_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return render_template('mfa_setup.html', qr_image_base64=qr_image_base64)

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        return render_template('dashboard.html')
    else:
        flash("You need to log in first.")
        return redirect(url_for('login'))

# Allowed file extensions and max file size (5 MB)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def file_size_ok(file):
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)  # Reset file pointer
    return file_length <= MAX_FILE_SIZE

@app.route('/promote_user/<email>', methods=['POST'])
def promote_user(email):
    # Your logic for promoting the user
    return redirect(url_for('admin_dashboard'))


@app.route('/demote_user/<string:email>', methods=['POST'])
def demote_user(email):
    # Logic to demote the user by email
    return redirect(url_for('admin_dashboard'))



@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part in the request.")
            return redirect(url_for('dashboard'))

        file = request.files['file']

        if file.filename == '':
            flash("No selected file.")
            return redirect(url_for('dashboard'))

        if file and allowed_file(file.filename) and file_size_ok(file):
            filename = secure_filename(file.filename)
            password = request.form.get('password')

             # Hash the password using sha256 to create an AES key
            aes_key = sha256(password.encode()).digest()

            # Read the file content
            file.seek(0)  # Reset file pointer after checking size
            file_data = file.read()

            # Encrypt the file using AES-256-GCM (you need your own `encrypt_file` method)
            nonce, ciphertext = encrypt_file(file_data, aes_key)

            # Hash the password for later validation
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Save encrypted file and metadata to MongoDB
            mongo.db.files.insert_one({
                'filename': filename,
                'nonce': nonce,
                'ciphertext': ciphertext,
                'uploaded_by': session['email'],
                'delete_password': hashed_password,
                'timestamp': datetime.utcnow()
            })

            flash("File uploaded successfully.")
            return redirect(url_for('my_files'))
        else:
            flash("Invalid file type or file size exceeds the limit.")
            return redirect(url_for('dashboard'))

    return render_template('upload.html')
@app.route('/my_files', methods=['GET', 'POST'])
def my_files():
    if 'email' in session:
        user_email = session['email']
        
        # Fetch the user's uploaded files from MongoDB
        files = list(mongo.db.files.find({"uploaded_by": user_email}))
        
        # Count the number of files uploaded by the user
        files_count = mongo.db.files.count_documents({"uploaded_by": user_email})

        if request.method == 'POST':
            if 'delete' in request.form:
                file_id = request.form['file_id']
                delete_password = request.form['password']

                # Find the file by _id and ensure the file belongs to the user
                file = mongo.db.files.find_one({"_id": ObjectId(file_id), "uploaded_by": user_email})
                
                if file:
                    # Verify the delete password
                    if bcrypt.checkpw(delete_password.encode(), file['delete_password']):
                        # Delete the file
                        mongo.db.files.delete_one({"_id": ObjectId(file_id)})

                        # Log the deletion action for auditing
                        mongo.db.audit_logs.insert_one({
                            "timestamp": datetime.now(),
                            "action": "Deleted file",
                            "user": user_email,
                            "details": f"Deleted file ID: {file_id}, filename: {file['filename']}"
                        })
                        flash("File deleted successfully.")
                    else:
                        flash("Invalid password for file deletion.")
                else:
                    flash("File not found or you do not have permission to delete it.")
                
                return redirect(url_for('my_files'))

        return render_template('my_files.html', files=files, files_count=files_count)

    else:
        flash("You need to log in first.")
        return redirect(url_for('login'))
@app.route('/download', methods=['GET', 'POST'])
def download_file():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        filename = request.form.get('filename')
        password = request.form.get('password')

        # Fetch the encrypted file from the database
        file_entry = mongo.db.files.find_one({'filename': filename, 'uploaded_by': session['email']})

        if file_entry:
            # Derive the encryption key from the provided password
            aes_key = sha256(password.encode()).digest()

            nonce = file_entry['nonce']
            ciphertext = file_entry['ciphertext']

            try:
                # Decrypt the file (you need your own `decrypt_file` method)
                file_data = decrypt_file(nonce, ciphertext, aes_key)
                return send_file(
                    BytesIO(file_data),
                    as_attachment=True,
                    download_name=file_entry['filename']
                )
            except Exception as e:
                flash(f"An error occurred during file decryption: {str(e)}")
                return redirect(url_for('my_files'))
        else:
            flash("File not found.")
            return redirect(url_for('my_files'))

    return render_template('download.html')

# Route to share a file with another user
@app.route('/share', methods=['GET', 'POST'])
def share_file():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        recipient_email = request.form.get('recipient_email')
        encryption_key = request.form.get('encryption_key')

        # Verify recipient exists
        recipient = mongo.db.users.find_one({'email': recipient_email})
        if not recipient:
            flash("Recipient not found.")
            return redirect(url_for('dashboard'))

        # Encrypt and store the file
        filename = secure_filename(file.filename)
        aes_key = sha256(encryption_key.encode()).digest()
        file_data = file.read()
        nonce, ciphertext = encrypt_file(file_data, aes_key)
        hashed_key = bcrypt.hashpw(encryption_key.encode(), bcrypt.gensalt())

        # Store the file with metadata
        mongo.db.files.insert_one({
            'filename': filename,
            'nonce': nonce,
            'ciphertext': ciphertext,
            'sender': session['email'],
            'recipient': recipient_email,
            'delete_password': hashed_key,
            'access_attempts': 0,
            'status': 'pending',
            'timestamp': datetime.utcnow()
        })

        # Log the sharing action in the audit logs
        mongo.db.audit_logs.insert_one({
            'timestamp': datetime.utcnow(),
            'action': 'File Shared',
            'user': session['email'],
            'details': f"Shared file '{filename}' with {recipient_email}."
        })

        flash(f"File '{filename}' shared with {recipient_email}.")
        return redirect(url_for('dashboard'))

    # Render the share form if it's a GET request
    return render_template('share.html')

# Route to view received files
@app.route('/received_files', methods=['GET', 'POST'])
def received_files():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    user_email = session['email']

    # Retrieve files shared with the logged-in user
    shared_files = mongo.db.files.find({'recipient': user_email, 'status': 'pending'})

    # Log the action of viewing received files
    mongo.db.audit_logs.insert_one({
        'timestamp': datetime.now(timezone.utc),
        'action': 'View Received Files',
        'user': session['email'],
        'details': "Viewed received files."
    })

    # Render a page with a list of received files
    return render_template('received_files.html', shared_files=shared_files)
@app.route('/download_shared_file/<file_id>', methods=['GET', 'POST'])
def download_shared_file(file_id):
    if 'email' not in session:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard'))

    file_record = mongo.db.files.find_one({'_id': ObjectId(file_id), 'recipient': session['email']})
    if not file_record:
        flash("File not found or you don't have access to it.")
        return redirect(url_for('received_files'))

    if request.method == 'POST':
        encryption_key = request.form.get('encryption_key')
        aes_key = sha256(encryption_key.encode()).digest()

        # Increment access attempts
        access_attempts = file_record.get('access_attempts', 0)

        if access_attempts < 2:
            try:
                decrypted_data = decrypt_file(file_record['ciphertext'], aes_key, file_record['nonce'])

                # Log the successful download action
                mongo.db.audit_logs.insert_one({
                    'timestamp': datetime.utcnow(),
                    'action': 'Download Shared File',
                    'user': session['email'],
                    'details': f"Downloaded shared file '{file_record['filename']}'."
                })

                # Reset access attempts to zero on successful download
                mongo.db.files.update_one(
                    {'_id': ObjectId(file_id)},
                    {'$set': {'access_attempts': 0}}
                )

                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file_record['filename']
                )
            except Exception as e:
                # Log the failed decryption attempt with error details
                mongo.db.audit_logs.insert_one({
                    'timestamp': datetime.now(timezone.utc),
                    'action': 'Failed Decryption Attempt',
                    'user': session['email'],
                    'details': f"Failed to decrypt file '{file_record['filename']}' due to incorrect encryption key. Error: {str(e)}"
                })

                # Increment the access attempt counter
                mongo.db.files.update_one(
                    {'_id': ObjectId(file_id)},
                    {'$inc': {'access_attempts': 1}}
                )

                if access_attempts + 1 >= 2:
                    # Delete the file
                    mongo.db.files.delete_one({'_id': ObjectId(file_id)})

                    # Log the file deletion
                    mongo.db.audit_logs.insert_one({
                        'timestamp': datetime.now(timezone.utc),
                        'action': 'File Deleted Due to Failed Attempts',
                        'user': session['email'],
                        'details': f"File '{file_record['filename']}' deleted after multiple failed decryption attempts."
                    })

                flash("Decryption failed. Please check your encryption key.")
                return redirect(url_for('received_files'))
        else:
            # Handle case when attempts exceed the limit
            mongo.db.files.delete_one({'_id': ObjectId(file_id)})
            mongo.db.audit_logs.insert_one({
                'timestamp': datetime.utcnow(),
                'action': 'File Deleted Due to Failed Attempts',
                'user': session['email'],
                'details': f"File '{file_record['filename']}' deleted after exceeding decryption attempts."
            })

            flash("You have exceeded the maximum number of attempts. The file has been deleted.")
            return redirect(url_for('received_files'))

    return render_template('download_shared_file.html', file_id=file_id, filename=file_record['filename'])


# Profile route should be outside the download_file function
@app.route('/profile')
@requires_role('user')
def profile():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('profile.html', user=user)
    else:
        flash("You do  not have permission to access this.")
        return redirect(url_for('dashboard'))
    
@requires_role('user')
def profile():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('profile.html', user=user)
    else:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard'))
    
@app.route('/admin')
@requires_role('admin')
def admin_dashboard():
    if 'email' in session:
        files = mongo.db.files.find()
        users = mongo.db.users.find()
        return render_template('admin_dashboard.html', files=files, users=users)
    else:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard'))

# Assume you have a function that checks user roles
@app.route('/audit_logs', methods=['GET', 'POST'])
@requires_role('admin')
def view_audit_logs():
    if 'email' in session:
        # Fetch all audit logs from MongoDB
        logs = list(mongo.db.audit_logs.find().sort('timestamp', -1))

        if request.method == 'POST':
            # Handle CSV download
            def generate_csv():
                yield 'Timestamp,Action,User,Details\n'
                for log in logs:
                    yield f"{log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')},{log['action']},{log['user']},{log['details']}\n"

            response = Response(generate_csv(), mimetype='text/csv')
            response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
            return response

        # Render the template with the logs for viewing
        return render_template('audit_logs.html', logs=logs)
    else:
        flash("You Do not have the permission to access this.")
        return redirect(url_for('dashboard'))
    

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('email', None)
    session.pop('user_role', None)
    flash("Logged out successfully.")
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Start key rotation thread
    threading.Thread(target=schedule.run_pending, daemon=True).start()
    app.run(debug=True)
