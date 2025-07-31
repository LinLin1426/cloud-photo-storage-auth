
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, uuid, datetime

app = Flask(__name__)
app.secret_key = "your-secret-key"
UPLOAD_FOLDER = "static/uploads"
DB_FILE = "db.sqlite3"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            user_id INTEGER,
            upload_time TEXT,
            share_token TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.commit()

def get_user():
    if "user_id" in session:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, email FROM users WHERE id=?", (session["user_id"],))
            return c.fetchone()
    return None

@app.route("/")
def index():
    user = get_user()
    if not user:
        return redirect("/login")
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, filename, share_token FROM images WHERE user_id=?", (user[0],))
        images = c.fetchall()
    return render_template("dashboard.html", user=user, images=images)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])
        email = request.form["email"]
        with sqlite3.connect(DB_FILE) as conn:
            try:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))
                conn.commit()
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("用户名已存在")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE username=?", (username,))
            user = c.fetchone()
            if user and check_password_hash(user[1], password):
                session["user_id"] = user[0]
                return redirect("/")
        flash("用户名或密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect("/login")

@app.route("/upload", methods=["POST"])
def upload():
    user = get_user()
    if not user or "image" not in request.files:
        return redirect("/")
    file = request.files["image"]
    filename = secure_filename(file.filename)
    if filename:
        uid = str(uuid.uuid4())[:8]
        filename = uid + "_" + filename
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO images (filename, user_id, upload_time) VALUES (?, ?, ?)", 
                      (filename, user[0], str(datetime.datetime.now())))
            conn.commit()
    return redirect("/")

@app.route("/view/<int:image_id>")
def view_image(image_id):
    token = request.args.get("token", "")
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT filename, share_token FROM images WHERE id=?", (image_id,))
        row = c.fetchone()
        if not row:
            abort(404)
        filename, share_token = row
        if share_token and token == share_token:
            return send_from_directory(UPLOAD_FOLDER, filename)
        user = get_user()
        if user:
            c.execute("SELECT user_id FROM images WHERE id=?", (image_id,))
            owner_id = c.fetchone()[0]
            if user[0] == owner_id:
                return send_from_directory(UPLOAD_FOLDER, filename)
    abort(403)

@app.route("/share/<int:image_id>")
def share(image_id):
    user = get_user()
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT user_id FROM images WHERE id=?", (image_id,))
        row = c.fetchone()
        if not row or row[0] != user[0]:
            abort(403)
        token = str(uuid.uuid4())[:8]
        c.execute("UPDATE images SET share_token=? WHERE id=?", (token, image_id))
        conn.commit()
    link = request.host_url + f"view/{image_id}?token={token}"
    return f"<p>分享链接：<a href='{link}' target='_blank'>{link}</a></p><a href='/'>返回</a>"

@app.route("/delete", methods=["POST"])
def delete():
    user = get_user()
    ids = request.form.getlist("delete_ids")
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for image_id in ids:
            c.execute("SELECT filename FROM images WHERE id=? AND user_id=?", (image_id, user[0]))
            row = c.fetchone()
            if row:
                filepath = os.path.join(UPLOAD_FOLDER, row[0])
                if os.path.exists(filepath):
                    os.remove(filepath)
                c.execute("DELETE FROM images WHERE id=? AND user_id=?", (image_id, user[0]))
        conn.commit()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
