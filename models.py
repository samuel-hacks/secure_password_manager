from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), unique = True, nullable = False)
    hashed_password = db.Column(db.String(255), nullable = False)

    salt = db.Column(db.LargeBinary, nullable = False)

    passwords = db.relationship("Password", backref = "owner", lazy = True, cascade = "all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"

class Password(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    service_name = db.Column(db.String(100), nullable = False)
    encrypted_password = db.Column(db.LargeBinary, nullable = False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = False)

    def __repr__(self):
        return f"<Password for {self.service_name}"
