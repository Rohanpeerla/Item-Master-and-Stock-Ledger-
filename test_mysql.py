import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Rohan@1225",
        database="item"
    )
    print("✅ Connected successfully!")
    conn.close()
except mysql.connector.Error as err:
    print(f"❌ Error: {err}")
