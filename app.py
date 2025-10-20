import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

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

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug = True)

