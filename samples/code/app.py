import os
import sqlite3
from flask import Flask, request, jsonify

# Bad: Hardcoded credentials
DATABASE_URL = "postgresql://admin:password123@localhost:5432/mydb"
JWT_SECRET = "super-secret-key-12345"

# Bad: AWS credentials in code  
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

app = Flask(__name__)

@app.route('/users', methods=['GET'])
def get_users():
    # Bad: PII data exposed without protection
    users = [
        {
            "id": 1,
            "name": "John Doe", 
            "email": "john.doe@example.com",
            "phone": "555-123-4567",
            "ssn": "123-45-6789",
            "credit_card": "4532015112830366"
        },
        {
            "id": 2,
            "name": "Jane Smith",
            "email": "jane.smith@company.org", 
            "phone": "555-987-6543",
            "dob": "03/15/1985"
        }
    ]
    return jsonify(users)

@app.route('/login', methods=['POST'])
def login():
    # Bad: Direct database connection with hardcoded password
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Bad: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True)
