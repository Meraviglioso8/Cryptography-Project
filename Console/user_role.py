import sqlite3

sqlConnection = sqlite3.connect("userdata.db")
cursor = sqlConnection.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY,
    role VARCHAR(255) NOT NULL UNIQUE,
    create_user INTEGER NOT NULL DEFAULT 0,
    delete_user INTEGER NOT NULL DEFAULT 0,
    search_data INTEGER NOT NULL DEFAULT 0,
    insert_data INTEGER NOT NULL DEFAULT 0,
    update_data INTEGER NOT NULL DEFAULT 0,
    delete_data INTEGER NOT NULL DEFAULT 0
)
""")

role1, create_user1, delete_user1, search_data1, insert_data1, update_data1, delete_data1 = "admin", 1, 1, 1, 1, 1, 1
role2, search_data2, insert_data2, update_data2, delete_data2 = "normal", 1, 1, 1, 1

cursor.execute("INSERT INTO role_permissions (role, create_user, delete_user, search_data, insert_data, update_data, delete_data)\
                VALUES ( ?, ?, ?, ?, ?, ?, ?)", (role1, create_user1, delete_user1, search_data1, insert_data1, update_data1, delete_data1))
cursor.execute("INSERT INTO role_permissions (role, search_data, insert_data, update_data, delete_data)\
                VALUES ( ?, ?, ?, ?, ?)", (role2, search_data2, insert_data2, update_data2, delete_data2))

sqlConnection.commit()