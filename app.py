from flask import Flask, render_template, flash, request, redirect, url_for, session, send_from_directory
from flask_pymongo import PyMongo, ObjectId
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import secrets
import os

client = MongoClient('mongodb://localhost:27017')
db = client['wad']

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
DEFAULT_AVATAR_PATH = 'static/images/Default.jpg'

app = Flask(__name__)
app.secret_key = b'lBb/=EKXg=1}Xz$nQb2Z_*e!O2>Xq%'
app.config['UPLOAD_FOLDER'] = 'static/images/upload'

# Configure MongoDB connection
app.config["MONGO_URI"] = "mongodb://localhost:27017/wad"
mongo = PyMongo(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password, salt):
    # Concatenate the salt with the password
    salted_password = salt + password
    # Hash the salted password
    hashed_password = generate_password_hash(salted_password, method='pbkdf2:sha256')
    return hashed_password

def save_image_path_to_mongodb(username, image_path):
    db.users.update_one(
        {'username': username},
        {'$set': {'image_path': image_path}}
    )

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check username and password in MongoDB
        user = mongo.db.users.find_one({'username': username})

        if user:
            # Extract stored hash and salt from the user record
            stored_hash = user.get('hash', '')
            stored_salt = user.get('salt', '')

            # Check if the provided password matches the stored hash and salt
            if check_password_hash(stored_hash, stored_salt + password):
                # Authentication successful
                session['username'] = username
                return redirect(url_for('profile'))
            
    # Authentication failed, redirect back to login page
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Check if password and confirm_password match
            if password != confirm_password:
                flash("Passwords do not match")
                return redirect(url_for('home'))

            # Generate a random salt
            salt = secrets.token_hex(16)

            # Hash the password with the generated salt
            hashed_password = hash_password(password, salt)

            # Save the user information to MongoDB
            mongo.db.users.insert_one({
                'username': username,
                'hash': hashed_password,
                'salt': salt,
                'avatar_path': DEFAULT_AVATAR_PATH
            })

            flash('Registration successful. Please log in.')
            return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/profile')
def profile():
    # Check if the user is authenticated
    if 'username' in session:
        return render_template('profile.html', username=session.get('username'))
    else:
        # Redirect to the login page if not authenticated
        return redirect(url_for('home'))

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    avatar_path = None  # Default value

    if request.method == 'POST':
        # Check if a new password is provided
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password and confirm_password and new_password == confirm_password:
            # Extract the user's existing salt from MongoDB
            if 'username' in session:
                username = session['username']
                user = mongo.db.users.find_one({'username': username})

                if user:
                    # Generate a random salt
                    salt = secrets.token_hex(16)

                    # Hash the password with the generated salt
                    hashed_password = hash_password(new_password, salt)

                    # Update the password in the user's record
                    mongo.db.users.update_one({'_id': ObjectId(user['_id'])}, {'$set': {'hash': hashed_password, 'salt': salt}})

        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        if not allowed_file(file.filename):
            flash('Invalid file extension', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            # Ensure the 'avatars' directory exists
            avatars_folder = os.path.join(app.config['UPLOAD_FOLDER'])
            os.makedirs(avatars_folder, exist_ok=True)

            # Save the file with a secure filename
            filename = os.path.join(avatars_folder, secure_filename(file.filename))
            file.save(filename)

            # Update the user's avatar path in MongoDB
            if 'username' in session:
                username = session['username']
                user = mongo.db.users.find_one({'username': username})

                if user:
                    # Update the avatar path in the user's record
                    mongo.db.users.update_one({'_id': ObjectId(user['_id'])}, {'$set': {'avatar_path': filename}})
                    avatar_path = filename  # Update avatar_path variable

    # Pass the avatar_path to the template
    return render_template('edit.html', username=session.get('username'), avatar_path=avatar_path, os=os)  

@app.route('/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    # Clear the session and redirect to the login page
    session.clear()
    return redirect(url_for('home'))
    
@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403
    
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)