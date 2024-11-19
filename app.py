from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import binascii
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import time

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session handling
CORS(app)

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
