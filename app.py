from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import binascii
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import time
import sqlite3
import hashlib
import base64

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session handling
CORS(app)

def generate_id(components):
    """
    Generate a 16-byte hash-based ID from a list of components and return it as Base64.
    Each component is concatenated into a single string before hashing.
    
    Args:
        components (list): List of string components to include in the hash.

    Returns:
        str: Base64-encoded 16-byte hash.
    """
    # Join the components into a single string
    combined_data = ''.join(components).encode('utf-8')
    
    # Generate a 16-byte hash (MD5)
    hash_object = hashlib.md5(combined_data)  # Use MD5 for a 16-byte hash
    hash_bytes = hash_object.digest()
    
    # Encode the hash in Base64
    id_base64 = base64.b64encode(hash_bytes).decode('utf-8')
    return id_base64

def store_registration_data(key_id, owner_name, certificate, public_key, nonce, signature, timestamp):
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

        # Generate the unique Base64 ID using a list of components
        unique_id = generate_id([key_id, nonce, timestamp])

        conn = sqlite3.connect('data.db')  # Connect to SQLite database
        cursor = conn.cursor()

        # Create the table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registered_tokens (
                id TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                certificate TEXT NOT NULL,
                public_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                signature TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')

        # Insert the verified registration data
        cursor.execute('''
            INSERT INTO registered_tokens (id, key_id, owner_name, certificate, public_key, nonce, signature, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (unique_id, key_id_base64, owner_name, certificate_base64, public_key_base64, nonce_base64, signature_base64, timestamp))

        conn.commit()  # Commit the transaction
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()  # Close the database connection

# Route to serve the client-side script
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-challenge', methods=['POST'])
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
            "timestamp": time.time(),  # Current time for expiration check
        }

        return jsonify({"nonce": nonce, "certificate": certificate, "key_id":key_id})
    except Exception as e:
        return jsonify({"error": "Failed to generate challenge", "details": str(e)}), 500

@app.route('/verify-registration', methods=['POST'])
def verify_registration():
    """
    Verify the registration by checking the signature and timestamp for a given key_id.
    """
    try:
        # Extract data from the request
        key_id = request.json.get("key_id")
        signature_hex = request.json.get("signature")
        timestamp = request.json.get("timestamp")

        if not key_id or not signature_hex or not timestamp:
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

        if not public_key_hex or not nonce or not owner_name:
            return jsonify({"error": "Incomplete token data in session"}), 500

        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key_hex)
            public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            return jsonify({"error": f"Error loading public key: {str(e)}"}), 500

        # Recreate the combined data that was signed
        combined_data = (nonce + owner_name + timestamp).encode('utf-8')

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

            # If verification succeeds, store the data in the database
            store_registration_data(
                key_id, owner_name, certificate, public_key_hex, nonce, signature_hex, timestamp
            )

            return jsonify({"status": "success", "message": "Signature verified successfully."}), 200
        except Exception as e:
            return jsonify({"status": "failure", "message": f"Signature verification failed: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "Failed to verify registration", "details": str(e)}), 500

@app.before_request
def cleanup_session():
    """
    Clean up expired entries in the session.
    """
    if session:
        current_time = time.time()
        keys_to_delete = []

        for key, value in session.items():
            if isinstance(value, dict) and current_time - value.get("timestamp", 0) > 90:
                keys_to_delete.append(key)

        # Remove expired keys
        for key in keys_to_delete:
            session.pop(key, None)

if __name__ == '__main__':
    app.run(debug=True)
