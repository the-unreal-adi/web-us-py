from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)

# Route to serve the client-side script
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle data sent from the client
@app.route('/submit_data', methods=['POST'])
def submit_data():
    certficate = request.json.get("certficate")
    owner_name = request.json.get("owner_name")
    public_key = request.json.get("public_key")
    
    # save_to_db(certficate, owner_name, public_key)
    return jsonify({'status': 'success'})

def save_to_db(certficate, owner_name, public_key):
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS client_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate TEXT NOT NULL,
            owner_name TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        INSERT INTO client_data (certificate, owner_name, public_key)
        VALUES (?, ?, ?)
    ''', (certficate, owner_name, public_key))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    app.run(debug=True)
