import os
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

# Database (NeonDB URL or fallback SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chatterbox.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    user = db.relationship('User')

# Initialize DB
@app.before_first_request
def create_tables():
    db.create_all()

# Base layout
layout = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
.chat-box { height: 400px; overflow-y: auto; border: 1px solid #ccc; padding: 10px; background: #f8f9fa; }
.message { margin-bottom: 10px; }
.message strong { color: #0d6efd; }
textarea { resize: none; }
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('chat') }}">ChatterBox</a>
    <div>
      {% if 'user_id' in session %}
      <span class="navbar-text me-3">Logged in as {{ session['username'] }}</span>
      <a class="btn btn-outline-light btn-sm" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
      <a class="btn btn-outline-light btn-sm me-2" href="{{ url_for('login') }}">Login</a>
      <a class="btn btn-outline-light btn-sm" href="{{ url_for('register') }}">Register</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container">
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for category, message in messages %}
      <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
        {{ message }}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    {% endfor %}
  {% endif %}
{% endwith %}
{{ content|safe }}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
var chatBox = document.querySelector('.chat-box');
if(chatBox){ chatBox.scrollTop = chatBox.scrollHeight; }
</script>
</body>
</html>
"""

# Routes
@app.route('/')
def index():
    return redirect(url_for('chat') if 'user_id' in session else url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        db.session.add(User(username=username, password=hashed))
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    content = """
    <h2>Register</h2>
    <form method="post">
      <div class="mb-3"><label>Username</label><input class="form-control" type="text" name="username" required></div>
      <div class="mb-3"><label>Password</label><input class="form-control" type="password" name="password" required></div>
      <div class="mb-3"><label>Confirm Password</label><input class="form-control" type="password" name="confirm" required></div>
      <button class="btn btn-primary">Register</button>
    </form>
    """
    return render_template_string(layout, title="Register", content=content)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login successful!", "success")
            return redirect(url_for('chat'))
        flash("Invalid credentials", "danger")
        return redirect(url_for('login'))

    content = """
    <h2>Login</h2>
    <form method="post">
      <div class="mb-3"><label>Username</label><input class="form-control" type="text" name="username" required></div>
      <div class="mb-3"><label>Password</label><input class="form-control" type="password" name="password" required></div>
      <button class="btn btn-primary">Login</button>
    </form>
    """
    return render_template_string(layout, title="Login", content=content)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET','POST'])
def chat():
    if 'user_id' not in session:
        flash("Please log in first", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        content_text = request.form['content'].strip()
        if content_text:
            db.session.add(Message(user_id=session['user_id'], content=content_text))
            db.session.commit()
        return redirect(url_for('chat'))

    messages = Message.query.order_by(Message.id.asc()).all()
    chat_html = """
    <h2>Chat Room</h2>
    <div class="mb-3">
      <form method="post">
        <textarea class="form-control mb-2" name="content" placeholder="Type a message..." required></textarea>
        <button class="btn btn-primary">Send</button>
      </form>
    </div>
    <div class="chat-box">
    """
    for msg in messages:
        chat_html += f'<div class="message"><strong>{msg.user.username}:</strong> {msg.content}</div>'
    chat_html += "</div>"

    return render_template_string(layout, title="Chat", content=chat_html)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
