import uuid
import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from azure.storage.blob import BlobServiceClient
from azure.storage.fileshare import ShareServiceClient
import pyodbc

# Initialize Flask app and configuration
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# SQL Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://project3jkgserveradmin:Jaspreet%401998@project3jkgserver.database.windows.net/dbuser?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes&TrustServerCertificate=no&ConnectionTimeout=30'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Azure Configuration
DATABASE_CONFIG = {
    'server': 'project3jkgserver.database.windows.net',
    'database': 'dbuser',
    'username': 'project3jkgserveradmin',
    'password': 'Jaspreet@1998',
    'driver': '{ODBC Driver 18 for SQL Server}'
}
BLOB_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=project3kg;AccountKey=s+3v92URuio/ofGCroaPL3yW6w1GKikgqc1csBJArtHIkDYQhGvV4SAlWqcul/HRfIBBB03R0ezT+AStwhmyqg==;EndpointSuffix=core.windows.net"
BLOB_CONTAINER_NAME = "usercontainer"
FILE_SHARE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=project3kg;AccountKey=s+3v92URuio/ofGCroaPL3yW6w1GKikgqc1csBJArtHIkDYQhGvV4SAlWqcul/HRfIBBB03R0ezT+AStwhmyqg==;EndpointSuffix=core.windows.net"
FILE_SHARE_NAME = "userfileshare1"

# Initialize Azure services
blob_service_client = BlobServiceClient.from_connection_string(BLOB_STORAGE_CONNECTION_STRING)
file_service_client = ShareServiceClient.from_connection_string(FILE_SHARE_CONNECTION_STRING)

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model for SQLAlchemy
class User(UserMixin, db.Model):
    __tablename__ = 'Users'  # Table name matches your SQL table name

    # Column names match the ones in your database table
    id = db.Column('Id', db.Integer, primary_key=True)
    name = db.Column('Name', db.String(100))
    dob = db.Column('DOB', db.Date)
    profile_picture_url = db.Column('ProfilePictureUrl', db.String(255))
    id_document_path = db.Column('IDDocumentPath', db.String(255))
    username = db.Column('Username', db.String(50), unique=True)
    password_hash = db.Column('PasswordHash', db.String(255))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database connection function
def get_db_connection():
    connection_string = f"DRIVER={DATABASE_CONFIG['driver']};" \
                        f"SERVER={DATABASE_CONFIG['server']};" \
                        f"DATABASE={DATABASE_CONFIG['database']};" \
                        f"UID={DATABASE_CONFIG['username']};" \
                        f"PWD={DATABASE_CONFIG['password']}"
    return pyodbc.connect(connection_string)

# Function to generate a unique filename
def generate_unique_filename(filename):
    return f"{uuid.uuid4().hex}_{filename}"

# Routes for the web application

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        username = request.form['username']
        password = request.form['password']

        # Hash the password before storing
        password_hash = generate_password_hash(password)

        # Create the user
        new_user = User(name=name, dob=dob, username=username, password_hash=password_hash)

        # Upload profile picture to Azure Blob Storage with a unique name
        profile_picture = request.files['profile_picture']
        if profile_picture:
            unique_filename = generate_unique_filename(profile_picture.filename)
            blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=unique_filename)
            blob_client.upload_blob(profile_picture, overwrite=True)  # Allow overwriting if file exists
            new_user.profile_picture_url = blob_client.url

        # Upload ID document to Azure File Share with a unique name
        id_document = request.files['id_document']
        if id_document:
            unique_filename = generate_unique_filename(id_document.filename)
            directory_client = file_service_client.get_share_client(FILE_SHARE_NAME).get_directory_client("user_documents")
            file_client = directory_client.get_file_client(unique_filename)  # Correct method to get the file client
            file_client.upload_file(id_document)  # Upload the ID document
            new_user.id_document_path = f"https://{file_service_client.account_name}.file.core.windows.net/{FILE_SHARE_NAME}/user_documents/{unique_filename}"

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user in the database
        user = User.query.filter_by(username=username).first()

        # Check if the password matches
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))

        flash('Invalid credentials!', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user_profile')
@login_required
def user_profile():
     # Get the ID document URL
    id_document_url = current_user.id_document_path
    return render_template('user_profile.html', user=current_user, id_document_url=id_document_url)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        profile_picture = request.files['profile_picture']
        id_document = request.files['id_document']

        # Update user info
        current_user.name = name
        current_user.dob = dob

        # Upload profile picture to Azure Blob Storage with a unique name
        if profile_picture:
            unique_filename = generate_unique_filename(profile_picture.filename)
            blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=unique_filename)
            blob_client.upload_blob(profile_picture, overwrite=True)
            current_user.profile_picture_url = blob_client.url

        # Upload ID document to Azure File Share with a unique name
        if id_document:
            unique_filename = generate_unique_filename(id_document.filename)
            directory_client = file_service_client.get_share_client(FILE_SHARE_NAME).get_directory_client("user_documents")
            file_client = directory_client.get_file_client(unique_filename)  # Correct method to get the file client
            file_client.upload_file(id_document)
            current_user.id_document_path = f"https://{file_service_client.account_name}.file.core.windows.net/{FILE_SHARE_NAME}/user_documents/{unique_filename}"

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile'))

    return render_template('edit_profile.html', user=current_user)

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    # Delete user from database and storage
    if current_user.profile_picture_url:
        blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=current_user.profile_picture_url.split('/')[-1])
        blob_client.delete_blob()

    if current_user.id_document_path:
        file_client = file_service_client.get_share_client(FILE_SHARE_NAME).get_directory_client("user_documents").get_file_client(current_user.id_document_path.split('/')[-1])
        file_client.delete_file()

    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash('Account deleted successfully!', 'success')
    return redirect(url_for('register'))

if __name__ == '__main__':
    app.run(debug=True)
