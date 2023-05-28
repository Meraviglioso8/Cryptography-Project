import sqlite3

sqlConnection = sqlite3.connect("userdata.db")
cursor = sqlConnection.cursor()

cursor.execute("SELECT * FROM userdata")
rows = cursor.fetchall()

for row in rows:
    print (row)

cursor.close()
sqlConnection.close()
