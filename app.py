from __future__ import annotations
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Dict, Any
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    posts = db.relationship('Post', backref='author_user', lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'content': self.content,
            'user_id': self.user_id,
        }


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


# Ensure DB exists
with app.app_context():
    db.create_all()


@app.route('/')
def root():
    return redirect(url_for('list_posts'))


# HTML pages
@app.route('/posts')
def list_posts():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)


@app.route('/posts/<int:post_id>')
def post_detail(post_id: int):
    post = Post.query.get_or_404(post_id)
    return render_template('post_detail.html', post=post)


@app.route('/posts/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        author = current_user.username
        if not title or not content:
            flash('Title and content are required.', 'error')
            return render_template('new_post.html', title=title, content=content)
        post = Post(title=title, author=author, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Post created.', 'success')
        return redirect(url_for('post_detail', post_id=post.id))
    return render_template('new_post.html')


@app.route('/posts/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id: int):
    post = Post.query.get_or_404(post_id)
    if post.user_id and post.user_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title or not content:
            flash('Title and content are required.', 'error')
            return render_template('edit_post.html', post=post)
        post.title = title
        post.content = content
        db.session.commit()
        flash('Post updated.', 'success')
        return redirect(url_for('post_detail', post_id=post.id))
    return render_template('edit_post.html', post=post)


@app.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id: int):
    post = Post.query.get_or_404(post_id)
    if post.user_id and post.user_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.', 'success')
    return redirect(url_for('list_posts'))


# Auth
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.', 'error')
            return render_template('register.html')
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('list_posts'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('list_posts'))


# RESTful API
@app.route('/api/posts', methods=['GET'])
def api_list_posts():
    posts = Post.query.order_by(Post.id.desc()).all()
    return jsonify([p.to_dict() for p in posts])


@app.route('/api/posts/<int:post_id>', methods=['GET'])
def api_get_post(post_id: int):
    post = Post.query.get_or_404(post_id)
    return jsonify(post.to_dict())


@app.route('/api/posts', methods=['POST'])
@login_required
def api_create_post():
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()
    author = current_user.username
    if not title or not content:
        return jsonify({'error': 'title and content are required'}), 400
    post = Post(title=title, author=author, content=content, user_id=current_user.id)
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_dict()), 201


@app.route('/api/posts/<int:post_id>', methods=['PUT'])
@login_required
def api_update_post(post_id: int):
    post = Post.query.get_or_404(post_id)
    if post.user_id and post.user_id != current_user.id:
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    title = data.get('title')
    content = data.get('content')
    if title is not None:
        post.title = title.strip()
    if content is not None:
        post.content = content.strip()
    db.session.commit()
    return jsonify(post.to_dict())


@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
@login_required
def api_delete_post(post_id: int):
    post = Post.query.get_or_404(post_id)
    if post.user_id and post.user_id != current_user.id:
        return jsonify({'error': 'forbidden'}), 403
    db.session.delete(post)
    db.session.commit()
    return '', 204


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
