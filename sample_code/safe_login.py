import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

username = input("Username: ")

cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

print(cursor.fetchall())
