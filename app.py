import os
from flask import Flask, render_template, request, redirect, url_for, flash, session

from models import db, User, Password
from crypto import hash_password, verify_password, derive_key, encrypt_data, decrypt_data

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = "a-very-secret-key-that-you-should-change"
    db_path = os.path.join(os.path.dirname(__file__), "instance", "passwords.db")
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)

    with app.app_context():
        db.create_all()

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))
    
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "error")
                return redirect(url_for("register"))

            salt = os.urandom(16)
            hashed = hash_password(password)
            new_user = User(username=username, hashed_password=hashed, salt=salt)
            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        return render_template('register.html')
    
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = User.query.filter_by(username=username).first()

            if user and verify_password(user.hashed_password, password):
                session.clear()
                session["user_id"] = user.id
                session["encryption_key"] = derive_key(password, user.salt).hex()
                flash("Logged in successfully!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.", "error")
                return redirect(url_for("login"))

        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard():
        if 'user_id' not in session or "encryption_key" not in session:
            flash("You must be logged in to view this page.", "error")
            return redirect(url_for("login"))
        
        user = db.session.get(User, session["user_id"])
        
        encryption_key = bytes.fromhex(session["encryption_key"])

        decrypted_passwords = []
        for pwd in user.passwords:
            decrypted_pwd_bytes = decrypt_data(pwd.encrypted_password, encryption_key)
            if decrypted_pwd_bytes:
                decrypted_passwords.append({
                    "service_name": pwd.service_name,
                    "password": decrypted_pwd_bytes.decode("utf-8", "ignore")
                })

        return render_template('dashboard.html', username=user.username, passwords=decrypted_passwords)

    @app.route("/add_password", methods=["POST"])
    def add_password():
        if 'user_id' not in session or "encryption_key" not in session:
            return redirect(url_for("login"))

        service_name = request.form.get("service_name")
        password_to_save = request.form.get("password")

        if not service_name or not password_to_save:
            flash("Service name and password are required.", "error")
            return redirect(url_for("dashboard"))

        encryption_key = bytes.fromhex(session["encryption_key"])
        encrypted_pwd = encrypt_data(password_to_save.encode(), encryption_key)

        new_password = Password(
            service_name=service_name,
            encrypted_password=encrypted_pwd,
            user_id=session["user_id"]
        )
        db.session.add(new_password)
        db.session.commit()

        flash(f"Password for {service_name} saved successfully!", "success")
        return redirect(url_for("dashboard"))
    
    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)

