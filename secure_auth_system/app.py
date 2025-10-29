from flask import Flask, render_template, request, jsonify, redirect,url_for,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt, jwt, datetime
from config import Config
from models import db, User

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()
    print("✅ Database aur tables create ho gaye!")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            return render_template("register.html", msg="Email already registered")

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


# ------------------ LOGIN PAGE ------------------ #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            token = jwt.encode(
                {"user_id": user.id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                app.config["SECRET_KEY"], algorithm="HS256"
            )
            session['token'] = token
            return redirect(url_for('dashboard'))
        else:
            return render_template("login.html", msg="Invalid credentials")
    return render_template('login.html')


# ------------------ DASHBOARD PAGE ------------------ #
@app.route('/dashboard')
def dashboard():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    try:
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(decoded["user_id"])
        return render_template('dashboard.html', user=user)
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        return redirect(url_for('login'))


# ------------------ LOGOUT ------------------ #
@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.secret_key = Config.SECRET_KEY
    app.run(debug=True)