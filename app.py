from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import binascii
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import secrets
import time
import sqlite3
import base64
import hashlib

USER_ID = "admin"

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
        
        combined_data = '|'.join(components).encode('utf-8')
        
        hash_object = hashlib.sha256(combined_data)
        digest = hash_object.hexdigest()
        return digest
    except Exception as e:
        print(f"Error: {e}")
        return None
 
def generate_base64_id(components):
    # Join the components into a single string
    combined_data = '|'.join(components).encode('utf-8')
    
    hash_object = hashlib.sha1(combined_data)  
    hash_bytes = hash_object.digest()
    
    # Encode the hash in Base64
    id_base64 = base64.b64encode(hash_bytes).decode('utf-8')
    return id_base64
    
def verify_signature(public_key, signature, digest_hex, timestamp):
    """
    Verify a digital signature using RSA-PKCS#1 v1.5 and SHA-256.
    """
    try:
        if not all([public_key, signature, digest_hex, timestamp]):
            raise ValueError("Insufficient verification data")
    
        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key)
            public_key_final = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            raise

        # Recreate the combined data that was signed
        combined_data = '|'.join([digest_hex, timestamp]).encode('utf-8')

        # Decode the received signature from hex
        signature_final = binascii.unhexlify(signature)

        try:
            # Verify the signature using RSA-PKCS1 v1.5 padding with SHA-256
            public_key_final.verify(
                signature_final,
                combined_data,  # Hash of the data
                padding=padding.PKCS1v15(),  # PKCS#1 v1.5 padding
                algorithm=hashes.SHA256()  # Explicitly specify the hash algorithm
            )  
            return True
        except Exception as e:
            raise Exception("Signature verification failed.") 
    except Exception as e:
        print(f"Error: {e}")
        return False
    
def is_fresh_timestamp(timestamp_str: str, allowed_drift_minutes: int = 5) -> bool:
    try:
        # Parse the incoming ISO 8601 timestamp with timezone
        request_time = datetime.fromisoformat(timestamp_str)
        
        # Ensure timestamp is timezone-aware
        if request_time.tzinfo is None:
            raise ValueError("Timestamp must be timezone-aware")

        # Get current UTC time
        now = datetime.now(timezone.utc)

        # Calculate allowed drift
        allowed_drift = timedelta(minutes=allowed_drift_minutes)

        # Check if timestamp is within the allowed time window
        if abs(now - request_time) <= allowed_drift:
            return True
        else:
            return False

    except ValueError as ve:
        print(f"Invalid timestamp format: {ve}")
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
                user_id TEXT NOT NULL,
                certificate TEXT NOT NULL,
                public_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                signature TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_mac TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                last_signed TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY,
                msg_content TEXT NOT NULL,
                user_id TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                key_id TEXT,
                signature TEXT,
                signer TEXT,
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

def store_registration_data(unique_id, key_id, owner_name, user_id, certificate, public_key, nonce, signature, client_id, client_mac, client_ip, domain, timestamp):
    """
    Store the verified registration data in the 'registered_tokens' SQLite database table.
    All fields except the ID are stored in Base64 format. The ID is derived from a hash of provided components.
    """
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        # Begin a transaction
        conn.execute("BEGIN")

        # Insert the verified registration data
        cursor.execute('''
            INSERT INTO registered_tokens (reg_id, key_id, owner_name, user_id, certificate, public_key, nonce, signature, client_id, client_mac, client_ip, domain, timestamp, last_signed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (unique_id, key_id, owner_name, user_id, certificate, public_key, nonce, signature, client_id, client_mac, client_ip, domain, timestamp, timestamp,))

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

def check_reg_status(reg_id, key_id, user_id, domain):
    try:
        conn = sqlite3.connect('signData.db')  
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM registered_tokens WHERE reg_id = ? AND key_id = ? AND user_id = ? AND domain = ?", (reg_id, key_id, user_id, domain))
        result = cursor.fetchone()

        if not result:
            return False
        
        owner_name = result[2]
        public_key_hex = result[5]
        nonce = result[6]
        signature_hex = result[7]
        client_id = result[8]
        client_ip = result[10]
        timestamp = result[12]

        derived_reg_id = generate_base64_id([client_id, key_id, domain, user_id])
        if derived_reg_id != reg_id:
            return False
        
        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key_hex)
            public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            return jsonify({"error": f"Error loading public key: {str(e)}"}), 500

        # Recreate the combined data that was signed
        combined_data = '|'.join([reg_id, nonce, owner_name, timestamp, key_id, client_id, client_ip, domain, USER_ID]).encode('utf-8')

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
        
            return True
        except Exception as e:
            raise Exception("Signature verification failed.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if conn:
            conn.close()

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

        timestamp = datetime.now(timezone.utc).isoformat(timespec='microseconds') 

        conn.execute("BEGIN")
        cursor.execute('INSERT INTO messages (msg_id, msg_content, user_id, last_updated) VALUES (?, ?, ?, ?)', (msg_id, message, USER_ID, timestamp,))
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

        timestamp = datetime.now(timezone.utc).isoformat(timespec='microseconds') 

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

def fetch_public_key_signer(key_id):
    public_key = None
    owner_name = None
    try:
        conn = sqlite3.connect('signData.db')  
        cursor = conn.cursor()

        cursor.execute("SELECT public_key, owner_name FROM registered_tokens WHERE key_id = ?", (key_id,))
        result = cursor.fetchone()

        if result:
            public_key = str(result[0])
            owner_name = str(result[1])
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
        return public_key, owner_name

def load_verify_message_data():
    messages = []
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cursor.execute('SELECT msg_id, msg_content, last_updated FROM messages WHERE signature IS NULL ORDER BY last_updated DESC')
        unsigned_messages = [{"msg_id": row[0], "msg_content": row[1], "created_updated_on": row[2], "signed": "N", "verified": "N"} for row in cursor.fetchall()]
        
        cursor.execute('SELECT msg_id, msg_content, user_id, last_updated, key_id, signature, signer, sign_timestamp, ip_address FROM messages WHERE signature IS NOT NULL ORDER BY key_id, last_updated DESC')
        signed_messages = [{"msg_id": row[0], "msg_content": row[1], "user_id": row[2], "created_updated_on": row[3], "key_id": row[4], "signature": row[5], "signer": row[6], "signed_on": row[7], "ip": row[8], "signed": "Y", "verified": "N"} for row in cursor.fetchall()]

        public_key = None
        current_key_id = None 
        for msg in signed_messages:
            key_id = msg.get("key_id")
            signature = msg.get("signature")
            timestamp = msg.get("signed_on")
            msg_id = msg.get("msg_id")
            msg_content = msg.get("msg_content")
            user = msg.get("user_id")
            created_updated_on = msg.get("created_updated_on")
            ip = msg.get("ip")

            if key_id != current_key_id:
                public_key, owner_name = fetch_public_key_signer(key_id)
                current_key_id = key_id

            if public_key: 
                digest_hex = create_sha256_digest([msg_id, msg_content, user, created_updated_on, ip])
                if digest_hex:
                    if verify_signature(public_key, signature, digest_hex, timestamp):
                        msg["verified"] = "Y"

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

        cursor.execute('SELECT msg_id, msg_content, user_id, last_updated FROM messages WHERE msg_id = ?', (msg_id,))
        result = cursor.fetchone()

        if result:
            components = [str(result[0]), str(result[1]), str(result[2]), str(result[3])]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
        return components
    
def store_message_signature(msg_id, key_id, signature, signer, timestamp, ip_addr):
    try:
        conn = sqlite3.connect('signData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        conn.execute("BEGIN")
        cursor.execute('UPDATE messages SET key_id = ?, signature = ?, signer = ?, sign_timestamp = ?, ip_address = ? WHERE msg_id = ?', (key_id, signature, signer, timestamp, ip_addr, msg_id))

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
    return render_template('register.html', user_id=USER_ID)

@app.route('/save-edit')
def return_save_edit():
    return render_template('save_edit.html')

@app.route('/sign-verify')
def return_sign_verify():
    return render_template('sign_verify.html', user_id=USER_ID)

@app.route('/api/reg-status', methods=['POST'])
def reg_status():
    reg_id = request.json.get("reg_id")
    key_id = request.json.get("key_id")
    domain = request.json.get("domain")

    if not all([reg_id, key_id, domain]):
        return jsonify({"status": "failure"}), 403

    status = check_reg_status(reg_id, key_id, USER_ID, domain)

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
        
        if not all([certificate, key_id, owner_name, public_key, client_ip]):
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

        return jsonify({"nonce": nonce, "certificate": certificate, "key_id":key_id, "client_ip": client_ip}), 200
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
        domain = request.json.get("domain")

        if not all([unique_id, key_id, signature_hex, timestamp, client_id, client_mac, domain]):
            return jsonify({"error": "Missing required data"}), 400

        # Check if the key_id exists in the session
        token_data = session.get(key_id)
        if not token_data:
            return jsonify({"error": "Token data not found in session"}), 404
        
        # Validate the timestamp
        if not is_fresh_timestamp(timestamp):
            return jsonify({"error": "Timestamp is not fresh or valid"}), 400

        # Fetch required values from the session
        public_key_hex = token_data.get("public_key")
        nonce = token_data.get("nonce")
        owner_name = token_data.get("owner_name")
        certificate = token_data.get("certificate")
        client_ip = token_data.get("client_ip")

        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key_hex)
            public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            return jsonify({"error": f"Error loading public key: {str(e)}"}), 500

        # Recreate the combined data that was signed
        combined_data = '|'.join([unique_id, nonce, owner_name, timestamp, key_id, client_id, client_ip, domain, USER_ID]).encode('utf-8')

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
                "domain": domain,
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
        domain = reg_data.get("domain")
        timestamp = reg_data.get("timestamp")

        store_registration_data(
            reg_id, key_id, owner_name, USER_ID, certificate, public_key_hex, nonce, signature_hex, client_id, client_mac, client_ip, domain, timestamp
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
    
@app.route('/api/get-message-digest', methods=['POST'])
def get_message_digest():
    try:
        reg_id = request.json.get('reg_id')
        key_id = request.json.get('key_id')
        msg_ids = request.json.get('msg_ids')
        client_ip = request.remote_addr
        domain = request.json.get('domain')

        if not all([reg_id, key_id, msg_ids, client_ip]):
            return jsonify({"error": "Incomplete data to generate message digest"}), 400
        
        if not isinstance(msg_ids, list):
            return jsonify({"error": "msg_ids must be a list"}), 400
        
        status = check_reg_status(reg_id, key_id, USER_ID, domain)
        if not status:
            return jsonify({"error": "DSC Token not registered"}), 404
        
        digests = []
        for msg_id in msg_ids:
            components = get_digest_components(msg_id)
            if not components:
                print(f"Unable to get components for {msg_id}")
                pass
            
            components.append(client_ip) 
            
            digest = create_sha256_digest(components)
            if not digest:
                print(f"Unable to create digest for {msg_id}")
                pass

            digests.append({"digest_id": msg_id, "digest_value": digest})
        
        session["sign_"+reg_id] = {
            "digests": digests,
            "ip": client_ip,
            "stimestamp": time.time()
        }
        
        return jsonify({"digests": digests, "reg_id": reg_id, "key_id": key_id}), 200
    except Exception as e:
        print(f"Error getting message digest: {e}")
        return jsonify({"error": "Unable to get message digest"}), 500
    
@app.route('/api/verify-sign', methods=['POST'])
def verify_store_signature():
    try:
        reg_id = request.json.get('reg_id')
        key_id = request.json.get('key_id')
        signed_digests = request.json.get('signed_digests')
        domain = request.json.get('domain')

        if not all([reg_id, key_id, signed_digests]):
            return jsonify({"error": "Incomplete data to verify signature"}), 400
        
        if not isinstance(signed_digests, list):
            return jsonify({"error": "signed_digests must be a list"}), 400
        
        status = check_reg_status(reg_id, key_id, USER_ID, domain)
        if not status:
            return jsonify({"error": "DSC Token not registered"}), 404
        
        public_key, signer = fetch_public_key_signer(key_id)
        if not public_key:
            return jsonify({"error": "Public key not found."}), 404

        sign_data = session.get("sign_"+reg_id)
        if not sign_data:
            return jsonify({"error": "Session ID not found in session"}), 404
        
        digests = sign_data.get("digests")
        ip_addr = sign_data.get("ip")
  
        for digest in digests:
            msg_id = digest.get("digest_id")
            digest_value = digest.get("digest_value")

            signed_digest = next((item for item in signed_digests if item.get("sign_id") == msg_id), None)
            
            if not signed_digest:
                continue

            signature = signed_digest.get("sign_value")
            timestamp = signed_digest.get("timestamp")
            signed_digests.remove(signed_digest)
          
            if not all([signature, timestamp]):
                continue

            if not is_fresh_timestamp(timestamp):
                print(f"Timestamp {timestamp} is not fresh for msg_id {msg_id}")
                continue
             
            if verify_signature(public_key, signature, digest_value, timestamp):
                store_message_signature(msg_id, key_id, signature, signer, timestamp, ip_addr)

        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error verifyifying signature: {e}")
        return jsonify({"error": "Unable to verify signature"}), 500
    finally:
        session.pop("sign_"+reg_id, None)
    
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
