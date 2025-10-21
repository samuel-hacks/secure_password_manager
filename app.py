import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy

from crypto import hash_password, verify_password

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config["SECRET KEY"] = "a-very-secret-key-that-you-should-change"

    db_path = os.path.join(os.path.dirname(__file__), "instance", "password.db")
    
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)

    from models import User, Password

    with app.app_context():
        db.create_all()

    @app.route("/")

    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))
    
    @app.route("/register", methods = ["GET", "POST"])

    def register():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            if User.query.filter_by(username = username).first():
                flash("Username already exists.", "error")
                return redirect(url_for("register"))

            salt = os.random(16)
            hashed = hash_password(password)
            new_user = User(username = username, hashed_password = hashed, salt = salt)
            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        return render_template('register.html')
    
    @app.route("/login", methods = ["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = User.query.filter_by(username = username).first()

            if user and verify_password(user.hashed_password, password):
                session.clear()

                session["user_id"] = user.id
                flash("Logged in successfully!", "success")
                
                return redirect(url_for("dashboard"))
            
            else:
                flash("Invalid username or password,", "error")
                return redirect(url_for("login"))

        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard():
        if user_id not in session:
            flash("You must be logged in to view that page.", "error")
            return redirect(url_for("login"))
        
        user = User.query.get(session["user_id"])
        return f'<h1>Welcome, {user.username}!</h1><p>You are logged in.</p><a href="/logout">Logout</a>'
    
    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/debug-path")
    def debug_path():
        print(f"Flask App Root Path: {app.root_path}")
        return f"<h1>My application root path is:</h1><p>{app.root_path}</p>"
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug = True)

