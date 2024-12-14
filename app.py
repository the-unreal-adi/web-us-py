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
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

def create_sha256_digest(components):
    """
    Create a SHA-256 digest from a list of components.
    """
    try:
        if not components:
            raise ValueError("Empty digest component")
        
        if not isinstance(components, list):
            raise TypeError("Components must be a list.")
        
        combined_data = ''.join(components).encode('utf-8')
        
        hash_object = hashlib.sha256(combined_data)
        digest = hash_object.hexdigest()
        return digest
    except Exception as e:
        print(f"Error: {e}")
        return None
    
def base_64_decode(data):
    try:
        base64_bytes = base64.b64decode(data, validate=True)
        return binascii.hexlify(base64_bytes).decode('utf-8')  # Convert to Hex string
    except Exception:
        return data

def base_64_encode(data):
    try:
        hex_bytes = binascii.unhexlify(data)
        return base64.b64encode(hex_bytes).decode('utf-8')
    except Exception:
        return data

def verify_signature(public_key, signature, components, timestamp):
    """
    Verify a digital signature using RSA-PKCS#1 v1.5 and SHA-256.
    """
    try:
        if not all([public_key, signature, components, timestamp]):
            raise ValueError("Insufficient verification data")
        
        if not isinstance(components, list):
            raise TypeError("Components must be a list.")
        
        digest_hex = create_sha256_digest(components)
        if not digest_hex:
            raise ValueError("Digest creation failed")
        
        public_key_hex = base_64_decode(public_key)
        signature_hex = base_64_decode(signature)

        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key_hex)
            public_key_final = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            raise

        # Recreate the combined data that was signed
        combined_data = (digest_hex + timestamp).encode('utf-8')

        # Decode the received signature from hex
        signature_final = binascii.unhexlify(signature_hex)

        try:
            # Verify the signature using RSA-PKCS1 v1.5 padding with SHA-256
            public_key_final.verify(
                signature_final,
                combined_data,  # Hash of the data
                padding=padding.PKCS1v15(),  # PKCS#1 v1.5 padding
                algorithm=hashes.SHA256()  # Explicitly specify the hash algorithm
            )  
        except Exception as e:
            raise 

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
    
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
                last_updated TEXT NOT NULL,
                key_id TEXT,
                signature TEXT,
                sign_timestamp TEXT,
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

def check_reg_status(reg_id, key_id):
    status = False

    try:
        conn = sqlite3.connect('signData.db')  
        cursor = conn.cursor()

        key_id_base64 = base64.b64encode(key_id.encode('utf-8')).decode('utf-8')

        cursor.execute("SELECT * FROM registered_tokens WHERE reg_id = ? AND key_id = ?", (reg_id, key_id_base64,))
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

        timestamp = time.time()

        conn.execute("BEGIN")
        cursor.execute('INSERT INTO messages (msg_id, msg_content, last_updated) VALUES (?, ?, ?)', (msg_id, message, timestamp,))
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def update_message_data(msg_id, message):
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        timestamp = time.time()

        conn.execute("BEGIN")
        cursor.execute('UPDATE messages SET msg_content = ?, last_updated = ? WHERE msg_id = ?', (message, timestamp, msg_id))

        if cursor.rowcount == 0:
            raise sqlite3.Error("Error updating message data: No matching msg_id found.")
        
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def load_message_data():
    messages = []
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cursor.execute('SELECT msg_id, msg_content, last_updated FROM messages')
        messages = [{"msg_id": row[0], "msg_content": row[1], "created_updated_on": row[2]} for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
        return messages

def fetch_public_key(key_id):
    public_key = None

    try:
        conn = sqlite3.connect('signData.db')  
        cursor = conn.cursor()

        key_id_base64 = base_64_encode(key_id)

        cursor.execute("SELECT public_key FROM registered_tokens WHERE key_id = ?", (key_id_base64,))
        result = cursor.fetchone()

        if result:
            public_key = str(result[0])
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    return public_key

def load_verify_message_data():
    messages = []
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cursor.execute('SELECT msg_id, msg_content, last_updated FROM messages WHERE signature IS NULL')
        unsigned_messages = [{"msg_id": row[0], "msg_content": row[1], "created_updated_on": row[2], "signed": "N", "verified": "N"} for row in cursor.fetchall()]

        cursor.execute('SELECT msg_id, msg_content, last_updated, key_id, signature, sign_timestamp FROM messages WHERE signature IS NOT NULL ORDER BY key_id')
        signed_messages = [{"msg_id": row[0], "msg_content": row[1], "created_updated_on": row[2], "key_id": row[3], "signature": row[4], "signed_on": row[5], "signed": "Y", "verified": "N"} for row in cursor.fetchall()]

        public_key = None
        current_key_id = None
        for msg in signed_messages:
            key_id = msg.get("key_id")
            signature = msg.get("signature")
            timestamp = msg.get("signed_on")
            msg_id = msg.get("msg_id")
            msg_content = msg.get("msg_content")
            created_updated_on = msg.get("created_updated_on")

            if key_id != current_key_id:
                public_key = fetch_public_key(key_id)
                current_key_id = key_id

            if public_key:
                if verify_signature(public_key, signature, [msg_id, msg_content, created_updated_on], timestamp):
                    msg["verified"] = "Y"
            else:
                msg["signed"] = "N"

        messages.extend(unsigned_messages)
        messages.extend(signed_messages)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
        return messages

def get_digest_components(msg_id):
    components = None

    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cursor.execute('SELECT msg_id, msg_content, last_updated FROM messages WHERE msg_id = ?', (msg_id,))
        result = cursor.fetchone()

        if result:
            components = [str(result[0]), str(result[1]), str(2)]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
        return components
    
def store_message_signature(msg_id, key_id, signature, timestamp):
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        key_id_base64 = base64.b64encode(key_id.encode('utf-8')).decode('utf-8')
        signature_base64 = base64.b64encode(binascii.unhexlify(signature)).decode('utf-8')
 
        conn.execute("BEGIN")
        cursor.execute('UPDATE messages SET key_id = ?, signature = ?, sign_timestamp = ? WHERE msg_id = ?', (key_id_base64, signature_base64, timestamp, msg_id))

        if cursor.rowcount == 0:
            raise sqlite3.Error(f"Error storing signature for msg_id {e}.")
        
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

@app.route('/sign-verify')
def return_sign_verify():
    return render_template('sign_verify.html')

@app.route('/api/reg-status', methods=['POST'])
def reg_status():
    reg_id = request.json.get("reg_id")
    key_id = request.json.get("key_id")

    if not reg_id or not key_id:
        return jsonify({"status": "failure"}), 403

    status = check_reg_status(reg_id, key_id)

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

@app.route('/api/save-message', methods=['POST'])
def save_message():
    # Save the new message to the database
    message = request.json.get('message')
    if not message:
        return jsonify({"status": "failure", "message": "No message provided."}), 400
    
    try:
        store_message_data(message)

        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "failure", "message": f"Error: {str(e)}"}), 500
    
@app.route('/api/save-message/<msg_id>', methods=['PATCH'])
def edit_message(msg_id):
    try:
        msg_content = request.json.get("message")

        if not msg_content:
            return jsonify({"error": "Message content is required"}), 400

        update_message_data(msg_id, msg_content)

        return jsonify({"success": True, "message": "Message updated successfully!"}), 200
    except Exception as e:
        print(f"Error editing message: {e}")
        return jsonify({"error": "Failed to update message"}), 500

    
@app.route('/api/load-saved-messages', methods=['GET'])
def load_saved_messages():
    try:
        messages = load_message_data()

        return jsonify(messages), 200
    except Exception as e:
        print(f"Error loading messages: {e}")
        return jsonify({"error": "Unable to load messages"}), 500
    
@app.route('/api/load-verify-messages', methods=['GET'])
def load_verify_messages():
    try:
        messages = load_verify_message_data()

        return jsonify(messages), 200
    except Exception as e:
        print(f"Error loading messages: {e}")
        return jsonify({"error": "Unable to load messages"}), 500
    
@app.route('/api/get-message-digest/<msg_id>', methods=['POST'])
def get_message_digest(msg_id):
    try:
        reg_id = request.json.get('reg_id')
        key_id = request.json.get('key_id')

        if not all([reg_id, key_id]):
            return jsonify({"error": "Incomplete data to generate message digest"}), 400
        
        status = check_reg_status(reg_id, key_id)
        if not status:
            return jsonify({"error": "DSC Token not registered"}), 404
        
        components = get_digest_components(msg_id)
        if not components:
            return jsonify({"error": "Unable to fetch digest components."}), 404
        
        digest = create_sha256_digest(components)
        if not digest:
            return jsonify({"error": "Unable to create digest."}), 404
        
        session[msg_id] = {
            "components": components,
            "stimestamp": time.time()
        }
        
        return jsonify({"hash": digest, "reg_id": reg_id, "key_id": key_id}), 200
    except Exception as e:
        print(f"Error getting message digest: {e}")
        return jsonify({"error": "Unable to get message digest"}), 500
    
@app.route('/api/verify-sign/<msg_id>', methods=['POST'])
def verify_store_signature(msg_id):
    try:
        reg_id = request.json.get('reg_id')
        key_id = request.json.get('key_id')
        signature = request.json.get('signature')
        timestamp = request.json.get('timestamp')

        if not all([reg_id, key_id, signature, timestamp]):
            return jsonify({"error": "Incomplete data to verify signature"}), 400
        
        status = check_reg_status(reg_id, key_id)
        if not status:
            return jsonify({"error": "DSC Token not registered"}), 404
        
        public_key = fetch_public_key(key_id)

        sign_data = session.get(msg_id)
        if not sign_data:
            return jsonify({"error": "Message ID not found in session"}), 404
        
        components = sign_data.get("components")

        status = verify_signature(public_key, signature, components, timestamp)

        if not status:
            return jsonify({"error": "Unable to verify signature"}), 404
        
        store_message_signature(msg_id, key_id, signature, timestamp)
    except Exception as e:
        print(f"Error verifyifying signature: {e}")
        return jsonify({"error": "Unable to verify signature"}), 500
@app.before_request
def cleanup_session():
    """
    Clean up expired entries in the session.
    """
    if session:
        current_time = time.time()
        keys_to_delete = []

        for key, value in session.items():
            if isinstance(value, dict) and current_time - value.get("stimestamp", 0) > 30:
                keys_to_delete.append(key)

        # Remove expired keys
        for key in keys_to_delete:
            session.pop(key, None)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
