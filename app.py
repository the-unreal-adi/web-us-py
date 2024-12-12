from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import binascii
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import time
import sqlite3
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

def init_db():
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        # Begin a transaction
        conn.execute("BEGIN")

        # Create the table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registered_tokens (
                reg_id TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                certificate TEXT NOT NULL,
                public_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                signature TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_mac TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                last_signed TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY,
                msg_content TEXT NOT NULL,
                key_id TEXT,
                signature TEXT,
                ip_address TEXT
            )
        ''')

        conn.commit()  # Commit the transaction
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()  # Close the database connection

def store_registration_data(unique_id, key_id, owner_name, certificate, public_key, nonce, signature, client_id, client_mac, client_ip, timestamp):
    """
    Store the verified registration data in the 'registered_tokens' SQLite database table.
    All fields except the ID are stored in Base64 format. The ID is derived from a hash of provided components.
    """
    try:
        # Convert fields to Base64
        certificate_base64 = base64.b64encode(certificate.encode('utf-8')).decode('utf-8')
        public_key_base64 = base64.b64encode(public_key.encode('utf-8')).decode('utf-8')
        signature_base64 = base64.b64encode(binascii.unhexlify(signature)).decode('utf-8')
        nonce_base64 = base64.b64encode(nonce.encode('utf-8')).decode('utf-8')
        key_id_base64 = base64.b64encode(key_id.encode('utf-8')).decode('utf-8')

        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        # Begin a transaction
        conn.execute("BEGIN")

        # Insert the verified registration data
        cursor.execute('''
            INSERT INTO registered_tokens (reg_id, key_id, owner_name, certificate, public_key, nonce, signature, client_id, client_mac, client_ip, timestamp, last_signed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (unique_id, key_id_base64, owner_name, certificate_base64, public_key_base64, nonce_base64, signature_base64, client_id, client_mac, client_ip, timestamp, timestamp,))

        conn.commit()  # Commit the transaction
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        clear_junk_registration(unique_id)
        raise
    finally:
        if conn:
            conn.close()  # Close the database connection

def check_reg_status(reg_id):
    status = False

    try:
        conn = sqlite3.connect('signData.db')  
        cursor = conn.cursor()

        cursor.execute("SELECT reg_id FROM registered_tokens WHERE reg_id = ?", (reg_id,))
        result = cursor.fetchone()

        if result:
            status = True 
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    return status

def clear_junk_registration(reg_id):
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        conn.execute("BEGIN")
        
        cursor.execute("""
            DELETE FROM registered_tokens
            WHERE reg_id = ?
        """,(reg_id,))

        # Commit the transaction to save changes
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def store_message_data(message):
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        msg_id = base64.b64encode((secrets.token_hex(16)).encode('utf-8')).decode('utf-8')

        conn.execute("BEGIN")
        cursor.execute('INSERT INTO messages (msg_id, msg_content) VALUES (?, ?)', (msg_id, message,))
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

# Route to serve the client-side script
@app.route('/')
def return_index():
    return render_template('index.html')

@app.route('/register')
def return_register():
    return render_template('register.html')

@app.route('/save-edit')
def return_save_edit():
    return render_template('save_edit.html')

@app.route('/verify')
def return_verify():
    return render_template('verify.html')

@app.route('/api/reg-status', methods=['POST'])
def reg_status():
    reg_id = request.json.get("reg_id")

    if not reg_id:
        return jsonify({"status": "failure"}), 403

    status = check_reg_status(reg_id)

    if status:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "failure"}), 400

@app.route('/api/generate-challenge', methods=['POST'])
def generate_challenge():
    """
    Generate a nonce, associate it with the provided key_id,
    and store it in the session for up to 5 minutes.
    """
    try:
        # Extract data from request
        certificate = request.json.get("certficate")
        key_id = request.json.get("key_id")
        owner_name = request.json.get("owner_name")
        public_key = request.json.get("public_key")
        client_ip = request.remote_addr
        
        if not key_id or not certificate or not owner_name or not public_key:
            return jsonify({"error": "Missing required data"}), 400

        # Generate nonce
        nonce = secrets.token_hex(16)

        # Store details in the session with a timestamp
        session[key_id] = {
            "nonce": nonce,
            "certificate": certificate,
            "owner_name": owner_name,
            "public_key": public_key,
            "client_ip": client_ip,
            "stimestamp": time.time(),  
        }

        return jsonify({"nonce": nonce, "certificate": certificate, "key_id":key_id})
    except Exception as e:
        return jsonify({"error": "Failed to generate challenge", "details": str(e)}), 500

@app.route('/api/verify-registration', methods=['POST'])
def verify_registration():
    """
    Verify the registration by checking the signature and timestamp for a given key_id.
    """
    try:
        # Extract data from the request
        unique_id = request.json.get("reg_id")
        key_id = request.json.get("key_id")
        signature_hex = request.json.get("signature")
        timestamp = request.json.get("timestamp")
        client_id = request.json.get("client_id")
        client_mac = request.json.get("client_mac")

        if not unique_id or not key_id or not signature_hex or not timestamp or not client_id or not client_mac:
            return jsonify({"error": "Missing required data"}), 400

        # Check if the key_id exists in the session
        token_data = session.get(key_id)
        if not token_data:
            return jsonify({"error": "Key ID not found in session"}), 404

        # Fetch required values from the session
        public_key_hex = token_data.get("public_key")
        nonce = token_data.get("nonce")
        owner_name = token_data.get("owner_name")
        certificate = token_data.get("certificate")
        client_ip = token_data.get("client_ip")

        if not public_key_hex or not nonce or not owner_name:
            return jsonify({"error": "Incomplete token data in session"}), 500

        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key_hex)
            public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            return jsonify({"error": f"Error loading public key: {str(e)}"}), 500

        # Recreate the combined data that was signed
        combined_data = (nonce + owner_name + timestamp + key_id + client_id).encode('utf-8')

        # Decode the received signature from hex
        signature = binascii.unhexlify(signature_hex)

        try:
            # Verify the signature using RSA-PKCS1 v1.5 padding with SHA-256
            public_key.verify(
                signature,
                combined_data,  # Hash of the data
                padding=padding.PKCS1v15(),  # PKCS#1 v1.5 padding
                algorithm=hashes.SHA256()  # Explicitly specify the hash algorithm
            )  

            session[unique_id] = {
                "key_id": key_id,
                "owner_name": owner_name,
                "certificate": certificate,
                "public_key_hex": public_key_hex,
                "nonce": nonce,
                "signature_hex": signature_hex,
                "client_id": client_id,
                "client_mac": client_mac,
                "client_ip": client_ip,
                "timestamp": timestamp,
                "stimestamp": time.time(),
            }

            return jsonify({"status": "success", "message": "Signature verified successfully.", "reg_id": unique_id}), 200
        except Exception as e:
            return jsonify({"status": "failure", "message": f"Signature verification failed: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "Failed to verify registration", "details": str(e)}), 500
    finally:
        session.pop(key_id, None)

@app.route('/api/verify-registration', methods=['PATCH'])
def update_verification_status():
    try:
        reg_id = request.json.get("reg_id")

        reg_data = session.get(reg_id)
        if not reg_data:
            return jsonify({"error": "Registration ID not found in session"}), 404
        
        key_id = reg_data.get("key_id")
        owner_name = reg_data.get("owner_name")
        certificate = reg_data.get("certificate")
        public_key_hex = reg_data.get("public_key_hex")
        nonce = reg_data.get("nonce") 
        signature_hex = reg_data.get("signature_hex") 
        client_id = reg_data.get("client_id") 
        client_mac = reg_data.get("client_mac") 
        client_ip = reg_data.get("client_ip") 
        timestamp = reg_data.get("timestamp")

        store_registration_data(
            reg_id, key_id, owner_name, certificate, public_key_hex, nonce, signature_hex, client_id, client_mac, client_ip, timestamp
        )

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.pop(reg_id, None)

@app.route('/save-message', methods=['POST'])
def save_message():
    # Save the new message to the database
    message = request.form.get('message')
    if not message:
        return jsonify({"status": "failure", "message": "No message provided."}), 400
    
    try:
        store_message_data(message)

        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "failure", "message": f"Error: {str(e)}"}), 500
    
@app.route('/load-saved-messages', methods=['GET'])
def load_saved_messages():
    try:
        conn = sqlite3.connect('signData.db')
        cursor = conn.cursor()
        cursor.execute('SELECT msg_content FROM messages')
        messages = [row[0] for row in cursor.fetchall()]
        conn.close()
        return jsonify(messages), 200
    except Exception as e:
        print(f"Error loading messages: {e}")
        return jsonify({"error": "Unable to load messages"}), 500

@app.before_request
def cleanup_session():
    """
    Clean up expired entries in the session.
    """
    if session:
        current_time = time.time()
        keys_to_delete = []

        for key, value in session.items():
            if isinstance(value, dict) and current_time - value.get("stimestamp", 0) > 90:
                keys_to_delete.append(key)

        # Remove expired keys
        for key in keys_to_delete:
            session.pop(key, None)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
