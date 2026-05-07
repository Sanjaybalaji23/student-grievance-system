from flask import Flask, render_template, request, redirect, session, abort, url_for, flash
from flask_mysqldb import MySQL
import bcrypt
import re
import datetime
import time
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "super_secure_secret_key"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max limit
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

# -------------------------
# MySQL Configuration
# -------------------------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root123'
app.config['MYSQL_DB'] = 'grievance_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'   # ✅ FIX: use dict cursor so columns are named, not index-based

mysql = MySQL(app)

# -------------------------
# Rate Limiting
# -------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day"]
)

# -------------------------
# Helper: Audit Logger
# -------------------------
def log_action(user_id, action):
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO audit_logs(user_id, action, ip_address) VALUES (%s, %s, %s)",
            (user_id, action, request.remote_addr)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print(f"[Audit Log Error] {e}")

# -------------------------
# Helper: Auto Escalate
# -------------------------
def auto_escalate():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE complaints
            SET status = 'Escalated'
            WHERE status = 'Pending'
            AND created_at <= NOW() - INTERVAL 3 DAY
        """)
        affected = cur.rowcount
        mysql.connection.commit()
        cur.close()
        return affected
    except Exception as e:
        print(f"[Auto Escalate Error] {e}")
        return 0

# -------------------------
# RBAC Decorators
# -------------------------
def login_required(f):
    @wraps(f)   # ✅ FIX: @wraps prevents decorator conflicts
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)   # ✅ FIX: @wraps prevents decorator conflicts
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# -------------------------
# Session Timeout (15 mins)
# -------------------------
@app.before_request
def session_timeout():
    if 'user_id' in session:
        now = int(time.time())
        last_activity = session.get('last_activity')

        # ✅ FIX: Handle old datetime-type sessions gracefully
        if isinstance(last_activity, datetime.datetime):
            session['last_activity'] = now
            return

        if isinstance(last_activity, int):
            if now - last_activity > 900:  # 15 minutes
                session.clear()
                # ✅ FIX: Don't return redirect here — just let the next request handle it
                return

        session['last_activity'] = now

# -------------------------
# HOME
# -------------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# -------------------------
# REGISTER
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Basic validation
        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template('register.html')

        # Domain restriction
        if not re.match(r"^[a-zA-Z0-9._%+-]+@college\.edu\.in$", email):
            flash("Only @college.edu.in emails are allowed.", "error")
            return render_template('register.html')

        # Check if email already exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing = cur.fetchone()
        if existing:
            cur.close()
            flash("Email already registered. Please login.", "error")
            return render_template('register.html')

        # ✅ FIX: Hash password and decode to string before storing
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cur.execute(
            "INSERT INTO users(name, email, password, role) VALUES (%s, %s, %s, %s)",
            (name, email, hashed_pw, 'student')
        )
        mysql.connection.commit()
        cur.close()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# -------------------------
# LOGIN
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash("Please enter both email and password.", "error")
            return render_template('login.html')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            stored_password = user['password']  # ✅ FIX: use named key, not index

            # ✅ FIX: Always encode to bytes for bcrypt comparison
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                session['user_id'] = user['id']
                session['role'] = user['role']
                session['name'] = user['name']
                session['last_activity'] = int(time.time())

                log_action(user['id'], "User Logged In")
                return redirect(url_for('dashboard'))

        # ✅ FIX: Use flash instead of plain string return
        flash("Invalid email or password. Please try again.", "error")
        return render_template('login.html')

    return render_template('login.html')

# -------------------------
# DASHBOARD
# -------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", role=session.get('role'))

# -------------------------
# ADMIN PANEL
# -------------------------
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    stats = get_dashboard_stats()
    return render_template("admin_dashboard.html", stats=stats)

# -------------------------
# LOGOUT
# -------------------------
@app.route('/logout')
@login_required
def logout():
    log_action(session['user_id'], "User Logged Out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# -------------------------
# Complaint ID Generator
# -------------------------
def generate_complaint_id():
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM complaints")
    count = cur.fetchone()['cnt']
    cur.close()
    year = datetime.datetime.now().year
    return f"GRV-{year}-{str(count + 1).zfill(4)}"

# -------------------------
# SUBMIT COMPLAINT
# -------------------------
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '')
        priority = request.form.get('priority', '')

        if not title or not description or not category or not priority:
            flash("All fields are required.", "error")
            return render_template("submit_complaint.html")

        complaint_id = generate_complaint_id()

        # ✅ NEW: Handle File Upload
        media_path = None
        if 'media' in request.files:
            file = request.files['media']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                ext = os.path.splitext(filename)[1]
                unique_filename = f"{complaint_id}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                media_path = f"uploads/{unique_filename}"

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO complaints 
            (complaint_id, user_id, title, description, category, priority, media_path) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (complaint_id, session['user_id'], title, description, category, priority, media_path))
        mysql.connection.commit()
        cur.close()

        # ✅ LOG ACTION (existing)
        log_action(session['user_id'], f"Submitted Complaint {complaint_id}")

        # ✅ NEW: GET USER EMAIL
        cur = mysql.connection.cursor()
        cur.execute("SELECT email FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
        cur.close()

        if user:
            user_email = user['email']

            # ✅ NEW: SEND EMAIL
            send_email(
                user_email,
                "Complaint Submitted Successfully",
                f"""
Hello,

Your complaint has been successfully submitted.

Complaint ID: {complaint_id}
Category: {category}
Priority: {priority}

We will resolve your issue within 3 days.

Thank you,
Grievance Hub Team
"""
            )

        # ✅ EXISTING FLASH + REDIRECT
        flash(f"Complaint {complaint_id} submitted successfully!", "success")
        return redirect(url_for('my_complaints'))

    return render_template("submit_complaint.html")
# -------------------------
# MY COMPLAINTS
# -------------------------
@app.route('/my-complaints')
@login_required
def my_complaints():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT complaint_id, title, category, priority, status, created_at, media_path 
        FROM complaints 
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session['user_id'],))
    complaints = cur.fetchall()
    cur.close()
    return render_template("my_complaints.html", complaints=complaints)

# -------------------------
# ADMIN: ALL COMPLAINTS
# -------------------------
@app.route('/admin/complaints')
@login_required
@admin_required
def admin_complaints():
    auto_escalate()

    status = request.args.get('status')
    priority = request.args.get('priority')
    category = request.args.get('category')
    search = request.args.get('search')

    query = """
        SELECT complaint_id, title, category, priority, status, created_at, media_path 
        FROM complaints
        WHERE 1=1
    """
    params = []

    if status:
        query += " AND status = %s"
        params.append(status)
    if priority:
        query += " AND priority = %s"
        params.append(priority)
    if category:
        query += " AND category = %s"
        params.append(category)
    if search:
        query += " AND complaint_id LIKE %s"
        params.append(f"%{search}%")

    query += " ORDER BY created_at DESC"

    cur = mysql.connection.cursor()
    cur.execute(query, tuple(params))
    complaints = cur.fetchall()
    cur.close()

    return render_template("admin_complaints.html", complaints=complaints)

# -------------------------
# DASHBOARD STATS
# -------------------------
def get_dashboard_stats():
    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) as cnt FROM complaints")
    total = cur.fetchone()['cnt']

    cur.execute("SELECT COUNT(*) as cnt FROM complaints WHERE status='Pending'")
    pending = cur.fetchone()['cnt']

    cur.execute("SELECT COUNT(*) as cnt FROM complaints WHERE status='In Progress'")
    in_progress = cur.fetchone()['cnt']

    cur.execute("SELECT COUNT(*) as cnt FROM complaints WHERE status='Resolved'")
    resolved = cur.fetchone()['cnt']

    cur.execute("SELECT COUNT(*) as cnt FROM complaints WHERE status='Escalated'")
    escalated = cur.fetchone()['cnt']

    cur.close()

    return {
        "total": total,
        "pending": pending,
        "in_progress": in_progress,
        "resolved": resolved,
        "escalated": escalated
    }

# -------------------------
# ADMIN: UPDATE STATUS
# -------------------------
@app.route('/admin/update-status/<complaint_id>', methods=['POST'])
@login_required
@admin_required
def update_status(complaint_id):
    new_status = request.form['status']

    cur = mysql.connection.cursor()

    # ✅ Update status
    cur.execute("""
        UPDATE complaints 
        SET status = %s 
        WHERE complaint_id = %s
    """, (new_status, complaint_id))
    mysql.connection.commit()

    # ✅ Get user email
    cur.execute("""
        SELECT users.email FROM complaints
        JOIN users ON complaints.user_id = users.id
        WHERE complaints.complaint_id = %s
    """, (complaint_id,))
    user = cur.fetchone()
    cur.close()

    # ✅ Send email
    if user:
        user_email = user['email']

        send_email(
            user_email,
            "Complaint Status Updated",
            f"""
Hello,

Your complaint ID: {complaint_id}

Status has been updated to: {new_status}

Thank you,
Grievance Hub Team
"""
        )

    # ✅ Log + Flash
    log_action(session['user_id'], f"Updated status of {complaint_id} to {new_status}")
    flash(f"Status of {complaint_id} updated to {new_status}.", "success")

    return redirect(url_for('admin_complaints'))

# -------------------------
# ADMIN: AUDIT LOGS
# -------------------------
@app.route('/admin/audit-logs')
@login_required
@admin_required
def view_audit_logs():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT users.email, audit_logs.action, audit_logs.ip_address, audit_logs.timestamp
        FROM audit_logs
        JOIN users ON audit_logs.user_id = users.id
        ORDER BY audit_logs.timestamp DESC
    """)
    logs = cur.fetchall()
    cur.close()
    return render_template("audit_logs.html", logs=logs)
# -------------------------
# Email Configuration
# -------------------------
from flask_mail import Mail, Message

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'grievancehub07@gmail.com'
app.config['MAIL_PASSWORD'] = 'pjwa silq slcw gcjl'

mail = Mail(app)
# -------------------------
# Email Sender Function
# -------------------------
def send_email(to, subject, body):
    try:
        msg = Message(
            subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[to]
        )
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print("Email Error:", e)

# -------------------------
if __name__ == '__main__':
    app.run(debug=True)