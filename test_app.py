
import sqlite3

def handle_request(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # 1. Real SQL Injection Risk
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # 2. Real Code Execution Risk
    eval(user_input)
