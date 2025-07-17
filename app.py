from flask import Flask, render_template, request, redirect, url_for, session
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

USERS_FILE = "users.json"
APPOINTMENTS_FILE = "appointments.json"

SERVICE_PRICES = {
    "Saç": "350 TL",
    "Sakal": "100 TL",
    "Saç & Sakal": "400 TL",
    "Bakım": "250 TL"
}

def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def load_appointments():
    try:
        with open(APPOINTMENTS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_appointments(appointments):
    with open(APPOINTMENTS_FILE, "w") as f:
        json.dump(appointments, f, indent=4)

def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        password2 = request.form["password2"]

        users = load_users()

        if not username or not password:
            error = "Kullanıcı adı ve şifre boş olamaz."
            return render_template("register.html", error=error)

        if password != password2:
            error = "Şifreler eşleşmiyor."
            return render_template("register.html", error=error)

        if username in users:
            error = "Bu kullanıcı adı zaten alınmış."
            return render_template("register.html", error=error)

        # Burada method parametresi eklendi:
        users[username] = generate_password_hash(password, method="pbkdf2:sha256")
        save_users(users)

        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        users = load_users()

        hashed_pw = users.get(username)
        if hashed_pw and check_password_hash(hashed_pw, password):
            session["username"] = username
            return redirect(url_for("index"))
        else:
            error = "Hatalı kullanıcı adı veya şifre"
            return render_template("login.html", error=error)

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    error_message = None
    username = session["username"]

    if request.method == "POST":
        name = request.form["name"]
        service = request.form["service"]
        date = request.form["date"]
        time = request.form["time"]

        datetime_str = f"{date} {time}"
        try:
            appt_time = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M")
        except ValueError:
            error_message = "❌ Geçersiz tarih veya saat biçimi girdiniz."
            user_appointments = get_user_appointments(username)
            return render_template("index.html", appointments=user_appointments, error=error_message,
                                   form_data=request.form, prices=SERVICE_PRICES, username=username)

        appointments = load_appointments()

        for appt in appointments:
            if appt["datetime"] == datetime_str and appt["username"] == username:
                existing_service = appt["service"].lower()
                service_lower = service.lower()
                if (("saç" in existing_service and "sakal" in service_lower) or
                    ("sakal" in existing_service and "saç" in service_lower)):
                    error_message = ("❌ Randevu aldığınız tarih dolu. "
                                     "Sadece sakal randevusu için benimle iletişime geçin.")
                else:
                    error_message = "❌ Bu saat zaten dolu."
                user_appointments = get_user_appointments(username)
                return render_template("index.html", appointments=user_appointments, error=error_message,
                                       form_data=request.form, prices=SERVICE_PRICES, username=username)

        appointments.append({
            "username": username,
            "name": name,
            "service": service,
            "datetime": datetime_str
        })

        save_appointments(appointments)
        return redirect(url_for("index"))

    user_appointments = get_user_appointments(username)
    return render_template("index.html", appointments=user_appointments, error=None, form_data=None,
                           prices=SERVICE_PRICES, username=username)

def get_user_appointments(username):
    all_appointments = load_appointments()
    user_appointments = [a for a in all_appointments if a.get("username") == username]
    return sorted(user_appointments, key=lambda x: x["datetime"])

@app.route("/delete", methods=["POST"])
@login_required
def delete_appointment():
    datetime_str = request.form["datetime"]
    username = session["username"]

    appointments = load_appointments()
    appointments = [a for a in appointments if not (a["datetime"] == datetime_str and a["username"] == username)]
    save_appointments(appointments)
    return redirect(url_for("index"))

@app.route("/edit/<datetime_str>", methods=["GET", "POST"])
@login_required
def edit_appointment(datetime_str):
    username = session["username"]
    appointments = load_appointments()
    appt = next((a for a in appointments if a["datetime"] == datetime_str and a["username"] == username), None)
    if not appt:
        return redirect(url_for("index"))

    if request.method == "POST":
        name = request.form["name"]
        service = request.form["service"]
        date = request.form["date"]
        time = request.form["time"]

        new_datetime = f"{date} {time}"

        try:
            appt_time = datetime.strptime(new_datetime, "%Y-%m-%d %H:%M")
        except ValueError:
            error_message = "❌ Geçersiz tarih veya saat biçimi girdiniz."
            return render_template("edit.html", appt=appt, date=date, time=time, prices=SERVICE_PRICES, error=error_message)

        for other in appointments:
            if other["datetime"] == new_datetime and other["username"] == username and other != appt:
                error_message = "❌ Bu tarih ve saat zaten dolu."
                return render_template("edit.html", appt=appt, date=date, time=time, prices=SERVICE_PRICES, error=error_message)

        appointments = [a for a in appointments if not (a["datetime"] == datetime_str and a["username"] == username)]
        appointments.append({
            "username": username,
            "name": name,
            "service": service,
            "datetime": new_datetime
        })
        save_appointments(appointments)
        return redirect(url_for("index"))

    date, time = appt["datetime"].split(" ")
    return render_template("edit.html", appt=appt, date=date, time=time, prices=SERVICE_PRICES, error=None)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)
