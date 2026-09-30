from flask import Flask, render_template, request, Response
import os
import secrets
import sqlite3
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename


app = Flask(__name__)

# =========================================================
# CONFIGURATION
# =========================================================

UPLOAD_FOLDER = "uploads"
DATABASE = "database.db"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =========================================================
# ENCRYPTION KEY
# =========================================================

ENCRYPTION_KEY = os.environ.get("TRACELOCK_KEY")

if not ENCRYPTION_KEY:
    raise RuntimeError(
        "TRACELOCK_KEY is not set. "
        "Set it in PowerShell before starting the server."
    )

try:
    cipher = Fernet(ENCRYPTION_KEY.encode())

except Exception:

    raise RuntimeError(
        "Invalid TRACELOCK_KEY."
    )


# =========================================================
# DATABASE
# =========================================================

def get_db():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS documents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            token TEXT UNIQUE NOT NULL,

            filename TEXT NOT NULL,

            stored_filename TEXT NOT NULL,

            recipient_email TEXT NOT NULL,

            expiry TEXT NOT NULL,

            created_at TEXT NOT NULL

        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            token TEXT NOT NULL,

            filename TEXT NOT NULL,

            recipient_email TEXT NOT NULL,

            access_time TEXT NOT NULL,

            ip_address TEXT,

            status TEXT NOT NULL

        )
    """)

    # -----------------------------------------------------
    # Migration for existing database
    # -----------------------------------------------------

    columns = connection.execute(
        "PRAGMA table_info(documents)"
    ).fetchall()

    column_names = [
        column["name"]
        for column in columns
    ]

    if "stored_filename" not in column_names:

        connection.execute("""
            ALTER TABLE documents
            ADD COLUMN stored_filename TEXT
        """)

    connection.commit()

    connection.close()


init_db()


# =========================================================
# DELETE EXPIRED ENCRYPTED FILE
# =========================================================

def delete_expired_document(document):

    stored_filename = document["stored_filename"]

    # Old records may not have encrypted filename
    if not stored_filename:
        return False

    encrypted_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )

    if os.path.exists(encrypted_path):

        try:

            os.remove(encrypted_path)

            return True

        except OSError:

            return False

    return False


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# UPLOAD + ENCRYPT
# =========================================================

@app.route("/upload", methods=["POST"])
def upload():

    file = request.files.get("document")

    recipient_email = request.form.get(
        "recipient_email"
    )

    expiry = request.form.get("expiry")


    # -----------------------------------------------------
    # Validate file
    # -----------------------------------------------------

    if not file or file.filename == "":

        return "No file selected"


    if not file.filename.lower().endswith(".pdf"):

        return "Only PDF files are allowed"


    # -----------------------------------------------------
    # Validate email
    # -----------------------------------------------------

    if not recipient_email:

        return "Recipient email is required"


    # -----------------------------------------------------
    # Validate expiry
    # -----------------------------------------------------

    try:

        expiry_minutes = int(expiry)

    except (TypeError, ValueError):

        return "Invalid expiry time"


    if expiry_minutes not in [1, 5, 10, 30]:

        return "Invalid expiry option"


    # -----------------------------------------------------
    # Read original PDF
    # -----------------------------------------------------

    original_data = file.read()


    if not original_data:

        return "Uploaded file is empty"


    # -----------------------------------------------------
    # Generate secure token
    # -----------------------------------------------------

    token = secrets.token_urlsafe(32)


    # -----------------------------------------------------
    # Encrypt PDF
    # -----------------------------------------------------

    encrypted_data = cipher.encrypt(
        original_data
    )


    # -----------------------------------------------------
    # Secure original filename
    # -----------------------------------------------------

    original_filename = secure_filename(
        file.filename
    )


    # -----------------------------------------------------
    # Generate unique encrypted filename
    # -----------------------------------------------------

    stored_filename = (
        secrets.token_hex(16)
        + ".encrypted"
    )


    encrypted_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )


    # -----------------------------------------------------
    # Save encrypted document
    # -----------------------------------------------------

    with open(
        encrypted_path,
        "wb"
    ) as encrypted_file:

        encrypted_file.write(
            encrypted_data
        )


    # -----------------------------------------------------
    # Calculate expiry
    # -----------------------------------------------------

    created_at = datetime.now()

    expiry_time = (
        created_at
        + timedelta(minutes=expiry_minutes)
    )


    # -----------------------------------------------------
    # Store metadata
    # -----------------------------------------------------

    connection = get_db()

    connection.execute("""
        INSERT INTO documents
        (
            token,
            filename,
            stored_filename,
            recipient_email,
            expiry,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        token,
        original_filename,
        stored_filename,
        recipient_email,
        expiry_time.isoformat(),
        created_at.isoformat()
    ))

    connection.commit()

    connection.close()


    # -----------------------------------------------------
    # Viewer link
    # -----------------------------------------------------

    viewer_link = f"/view/{token}"


    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>
            TraceLock - Upload Successful
        </title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                background: #f4f4f4;
                padding: 50px;
            }}

            .card {{
                max-width: 650px;
                margin: auto;
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow:
                    0 0 15px rgba(0,0,0,0.15);
            }}

            a {{
                display: inline-block;
                padding: 10px 18px;
                background: #111;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin-right: 10px;
            }}

            .success {{
                color: green;
                font-weight: bold;
            }}

        </style>

    </head>

    <body>

        <div class="card">

            <h1>🔐 TraceLock</h1>

            <h2>Upload Successful!</h2>

            <p>
                <strong>File:</strong>
                {original_filename}
            </p>

            <p>
                <strong>Recipient:</strong>
                {recipient_email}
            </p>

            <p>
                <strong>Expires:</strong>
                {expiry_time}
            </p>

            <p class="success">
                🔒 Document encrypted successfully
            </p>

            <p>
                <strong>Access Token:</strong>
                {token}
            </p>

            <br>

            <a href="{viewer_link}">
                Open Secure Document
            </a>

            <a href="/dashboard">
                Dashboard
            </a>

        </div>

    </body>

    </html>
    """


# =========================================================
# VIEW DOCUMENT
# =========================================================

@app.route("/view/<token>")
def view_document(token):

    connection = get_db()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE token = ?
    """, (token,)).fetchone()

    connection.close()


    if not document:

        return """
        <h2>
            Invalid Document Link
        </h2>
        """, 404


    # -----------------------------------------------------
    # Check expiry
    # -----------------------------------------------------

    expiry_time = datetime.fromisoformat(
        document["expiry"]
    )


    if datetime.now() >= expiry_time:

        # Log expired access
        log_access(
            document,
            token,
            "EXPIRED"
        )

        # Delete encrypted file
        delete_expired_document(
            document
        )

        return """
        <!DOCTYPE html>

        <html>

        <head>

            <title>
                TraceLock - Expired
            </title>

            <style>

                body {{
                    font-family: Arial;
                    background: #f4f4f4;
                    text-align: center;
                    padding-top: 100px;
                }}

                .box {{
                    background: white;
                    width: 450px;
                    margin: auto;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow:
                        0 0 15px rgba(0,0,0,0.15);
                }}

            </style>

        </head>

        <body>

            <div class="box">

                <h1>
                    🚫 Access Denied
                </h1>

                <p>
                    This document has expired.
                </p>

                <p>
                    🔐 Encrypted file has been removed.
                </p>

            </div>

        </body>

        </html>
        """, 403


    # -----------------------------------------------------
    # Log allowed access
    # -----------------------------------------------------

    log_access(
        document,
        token,
        "ALLOWED"
    )


    # -----------------------------------------------------
    # Secure viewer
    # -----------------------------------------------------

    return render_template(
        "viewer.html",
        token=token,
        recipient_email=document[
            "recipient_email"
        ]
    )


# =========================================================
# DECRYPT + SERVE PDF
# =========================================================

@app.route("/document/<token>")
def document_file(token):

    connection = get_db()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE token = ?
    """, (token,)).fetchone()

    connection.close()


    if not document:

        return "Invalid document link", 404


    # -----------------------------------------------------
    # Check expiry BEFORE decryption
    # -----------------------------------------------------

    expiry_time = datetime.fromisoformat(
        document["expiry"]
    )


    if datetime.now() >= expiry_time:

        delete_expired_document(
            document
        )

        return """
        <h2>
            Access Denied
        </h2>

        <p>
            This document has expired.
        </p>

        <p>
            Encrypted file has been removed.
        </p>
        """, 403


    # -----------------------------------------------------
    # Get encrypted file
    # -----------------------------------------------------

    stored_filename = document[
        "stored_filename"
    ]


    if not stored_filename:

        return """
        <h2>
            Encryption Error
        </h2>

        <p>
            This document was created before
            encryption was enabled.
        </p>
        """, 500


    encrypted_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )


    if not os.path.exists(encrypted_path):

        return """
        <h2>
            Document Unavailable
        </h2>

        <p>
            The encrypted document is no longer available.
        </p>
        """, 404


    # -----------------------------------------------------
    # Read encrypted data
    # -----------------------------------------------------

    try:

        with open(
            encrypted_path,
            "rb"
        ) as encrypted_file:

            encrypted_data = (
                encrypted_file.read()
            )


        # -------------------------------------------------
        # Decrypt
        # -------------------------------------------------

        pdf_data = cipher.decrypt(
            encrypted_data
        )


    except InvalidToken:

        return """
        <h2>
            Security Error
        </h2>

        <p>
            Document decryption failed.
        </p>
        """, 500


    # -----------------------------------------------------
    # Send decrypted PDF to browser
    # -----------------------------------------------------

    return Response(
        pdf_data,
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                "inline; filename="
                + document["filename"]
        }
    )


# =========================================================
# ACCESS LOG
# =========================================================

def log_access(
    document,
    token,
    status
):

    connection = get_db()

    connection.execute("""
        INSERT INTO access_logs
        (
            token,
            filename,
            recipient_email,
            access_time,
            ip_address,
            status
        )

        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        token,
        document["filename"],
        document["recipient_email"],
        datetime.now().isoformat(),
        request.remote_addr,
        status
    ))

    connection.commit()

    connection.close()


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    connection = get_db()


    documents = connection.execute("""
        SELECT *
        FROM documents
        ORDER BY id DESC
    """).fetchall()


    total_documents = len(
        documents
    )


    active_links = 0

    expired_links = 0

    current_time = datetime.now()


    for document in documents:

        expiry_time = datetime.fromisoformat(
            document["expiry"]
        )


        if current_time < expiry_time:

            active_links += 1

        else:

            expired_links += 1


    total_accesses = connection.execute("""
        SELECT COUNT(*) AS total
        FROM access_logs
    """).fetchone()["total"]


    recent_logs = connection.execute("""
        SELECT *
        FROM access_logs
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()


    connection.close()


    return render_template(
        "dashboard.html",
        total_documents=total_documents,
        active_links=active_links,
        expired_links=expired_links,
        total_accesses=total_accesses,
        logs=recent_logs
    )


# =========================================================
# ALL LOGS
# =========================================================

@app.route("/logs")
def view_logs():

    connection = get_db()

    logs = connection.execute("""
        SELECT *
        FROM access_logs
        ORDER BY id DESC
    """).fetchall()

    connection.close()


    return render_template(
        "dashboard.html",
        total_documents="-",
        active_links="-",
        expired_links="-",
        total_accesses=len(logs),
        logs=logs
    )


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )