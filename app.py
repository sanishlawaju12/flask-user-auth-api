from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/user'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"message": "Missing fields"}),
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}),

    new_user = User(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        session['email'] = user.email
        return jsonify({"message": "Login successful"}), 
    else:
        return jsonify({"message": "Invalid email or password"}), 

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('email', None)
    return jsonify({"message": "Logout successful"}),

if __name__ == '__main__':
    app.run(debug=True)
