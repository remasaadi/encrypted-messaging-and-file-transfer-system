import socket
import struct
import threading
import os
import sqlite3
import time

DEFAULT_PORT = 1357
PORT_FILE = "myport.info"
DB_FILE = "defensive.db"

# פונקציה לקריאת הפורט מהקובץ
def get_port():
    if os.path.exists(PORT_FILE):
        with open(PORT_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()  # מסיר רווחים ותווי ירידת שורה

            if content.isdigit():  # בדיקה שהתוכן מורכב רק ממספרים
                return int(content)
            else:
                print(f"Error: Port file '{PORT_FILE}' is invalid or empty. Using default port {DEFAULT_PORT}.")
    else:
        print(f"Warning: Port file '{PORT_FILE}' not found. Using default port {DEFAULT_PORT}.")

    return DEFAULT_PORT


# יצירת בסיס נתונים אם לא קיים
def initialize_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
        id BLOB PRIMARY KEY,
        username TEXT UNIQUE,
        public_key BLOB,
        last_seen TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        to_client BLOB,
        from_client BLOB,
        type INTEGER,
        content BLOB
    )''')
    conn.commit()
    conn.close()

# פונקציה לטיפול בבקשות לקוח
def handle_client(conn, addr):
    try:
        while True:
            header = conn.recv(23)  # קריאה של הכותרת
            if not header:
                break
            client_id , version, code, payload_size = struct.unpack("<16s B H I", header)  # המרה ל-Little-Endian
            print(f"Debug: Client ID (Hex) = {client_id}")
            print(f"Debug: Version = {version}")
            print(f"Debug: Code = {code}")
            print(f"Debug: Payload Size = {payload_size}")

            payload = conn.recv(payload_size) if payload_size > 0 else b''
            response = process_request(client_id, code, payload)
            conn.send(response)
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

# פונקציה לעיבוד בקשות לקוח
def process_request(client_id, code, payload):
    if code == 600:  # רישום משתמש
        return register_user(payload)
    elif code == 601:  # בקשת רשימת משתמשים
        return list_users(client_id)
    elif code == 602:  # בקשת מפתח ציבורי
        return get_public_key(payload)
    elif code == 603:  # שמירת הודעה
        return store_message(client_id, payload)
    elif code == 604:  # הודעות ממתינות
        return fetch_messages(client_id)

# פונקציה לרישום משתמש חדש
def register_user(payload):
    username, public_key = payload[:255].decode().strip('\x00'), payload[255:]
    client_id = os.urandom(16)  # יצירת מזהה ייחודי
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO clients (id, username, public_key) VALUES (?, ?, ?)",
                       (client_id, username, public_key))
        conn.commit()
        conn.close()
        return struct.pack("<B H I 16s", 2, 2100, 16, client_id)
    except sqlite3.IntegrityError:
        return struct.pack("<B H I", 2, 9000, 0)  # שגיאה אם שם המשתמש קיים

# פונקציה להחזרת רשימת משתמשים
def list_users(requesting_client_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # שליפת כל המשתמשים מלבד המשתמש שביקש את הרשימה
    cursor.execute("SELECT id, username FROM clients WHERE id != ?", (requesting_client_id,))
    users = cursor.fetchall()
    conn.close()

    payload = b''

    for user in users:
        client_id = user[0]  # Client ID בגודל 16 בתים
        username = user[1].encode()[:255]  # ניקח עד 255 תווים בלבד
        username = username.ljust(255, b'\x00')  # מילוי באפסים (NULL-Terminated)

        payload += client_id + username  # הוספת הרשומה ל-Payload
    payload_size = len(payload)

    # יצירת הכותרת בפורמט Big-Endian
    response = struct.pack("<B H I", 2, 2101, payload_size) + payload

    return response

# פונקציה לשליפת מפתח ציבורי
def get_public_key(payload):
    client_name = payload.decode().strip('\x00')  # המרת הנתון לשם משתמש בפורמט הנכון

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, public_key FROM clients WHERE username = ?", (client_name,))
    result = cursor.fetchone()
    conn.close()

    if result:
        client_id, public_key = result
        payload_size = 16 + 160  # 176 בתים
        return struct.pack("<B H I 16s 160s", 2, 2102, payload_size, client_id, public_key)

    return struct.pack("<B H I", 2, 9000, 0)  # תשובת שגיאה

# פונקציה לאחסון הודעה
def store_message(from_client, payload):
    to_client, msg_type, content_size = struct.unpack("<16s B I", payload[:21])  # 16+1+4=21 בתים
    content = payload[21:21 + content_size]

    if msg_type == 1:
        return store_symmetric_key_request(from_client, payload)
    elif msg_type == 2:
        return store_symmetric_key(from_client, payload)
    elif msg_type == 3:
        return store_text_message(from_client, payload)
    elif msg_type == 4:
        return store_file(from_client, payload)

# פונקציה לשמירת בקשת מפתח סימטרי
def store_symmetric_key_request(from_client, payload):
    # פריסת ה־payload
    to_client, msg_type, content_size = struct.unpack("<16s B I", payload[:21])  # 16+1+4=21 בתים
    # חילוץ תוכן ההודעה מתוך ה־payload
    message_content = payload[21:21+content_size]
    # שמירה במסד הנתונים
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (to_client, from_client, type, content) VALUES (?, ?, ?, ?)",
                   (to_client, from_client, msg_type, message_content))
    conn.commit()
    message_id = cursor.lastrowid  # קבלת מזהה ההודעה שנשמרה
    conn.close()

    return send_response(to_client, message_id)

# פונקציה לשמירת מפתח סימטרי
def store_symmetric_key(from_client, payload):
    to_client, msg_type, content_size = struct.unpack("<16s B I", payload[:21])
    # חילוץ תוכן ההודעה מתוך ה־payload
    message_content = payload[21:21 + content_size]

    # חיבור למסד הנתונים ושמירת הנתונים
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO messages (to_client, from_client, type, content) VALUES (?, ?, ?, ?)",
                   (to_client, from_client, msg_type, message_content))
    conn.commit()
    message_id = cursor.lastrowid  # קבלת מזהה ההודעה שנשמרה
    conn.close()

    return send_response(to_client, message_id)

def store_text_message(from_client, payload):
    # פירוק הנתונים מה-payload
    to_client, msg_type, content_size = struct.unpack("<16s B I", payload[:21])
    content = payload[21:]  # קריאת תוכן ההודעה

    # שמירת ההודעה במסד הנתונים
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO messages (to_client, from_client, type, content)
        VALUES (?, ?, ?, ?)
    """, (to_client, from_client, msg_type, content))

    conn.commit()
    message_id = cursor.lastrowid  # קבלת מזהה ההודעה שנשמרה
    conn.close()
    return send_response(to_client, message_id)

def store_file(from_client, payload):
    # פירוק הנתונים מה-payload
    to_client_bytes, msg_type, content_size = struct.unpack("<16s B I", payload[:21])
    to_client = to_client_bytes.hex()
    file_content = payload[21:]  # קריאת תוכן הקובץ

    if len(file_content) != content_size:
        print("Error: Mismatch between declared and actual file content size")
        return None

    # שמירת הקובץ במסד הנתונים
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
            INSERT INTO messages (to_client, from_client, type, content)
            VALUES (?, ?, ?, ?)
        """, (to_client, from_client, msg_type, file_content))
    conn.commit()
    message_id = cursor.lastrowid  # קבלת מזהה ההודעה שנשמרה
    conn.close()
    return send_response(bytes.fromhex(to_client), message_id)

def send_response(to_client, message_id):
    version = 2  # מספר גירסת שרת
    response_code = 2103  # קוד תשובה עבור הודעה שנשלחה ללקוח
    payload_size = 20  # גודל התוכן בתשובה

    # בניית חבילת התשובה
    response = struct.pack("<B H I 16s I", version, response_code, payload_size, to_client , message_id)
    return response

# פונקציה לשליפת הודעות ממתינות
def fetch_messages(client_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()


    # שליפת הודעות המיועדות ללקוח הספציפי
    cursor.execute("SELECT id, from_client, type, content FROM messages WHERE to_client = ?", (client_id,))
    messages = cursor.fetchall()

    if not messages:
        print(f"\nאין הודעות זמינות עבור הלקוח {client_id.hex()}")

    # מחיקת ההודעות לאחר השליפה
    for msg in messages:
        cursor.execute("DELETE FROM messages WHERE id = ?", (msg[0],))

    conn.commit()
    conn.close()

    # בניית ה-payload להחזרת ההודעות
    payload = b''
    for msg in messages:
        message_id = struct.pack("<I", msg[0])  # Message ID (4 bytes)
        from_client = msg[1]  # 16 bytes
        message_type = struct.pack("<B", msg[2])  # Message Type (1 byte)
        message_size = struct.pack("<I", len(msg[3]))  # Message Size (4 bytes)
        content = msg[3]  # תוכן ההודעה

        # חיבור ההודעה לפורמט המתאים
        payload += from_client + message_id + message_type + message_size + content

    # יצירת התשובה בפורמט המלא
    response = struct.pack("<B H I", 2, 2104, len(payload)) + payload

    return response

# פונקציה ראשית להפעלת השרת
def main():
    initialize_db()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", get_port()))
    server_socket.listen()
    print("Server is running...")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    main()
