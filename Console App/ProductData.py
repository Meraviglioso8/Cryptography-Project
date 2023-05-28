import sqlite3

sqlConnection = sqlite3.connect("productdata.db")
cursor = sqlConnection.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS product (
    id INTEGER PRIMARY KEY,
    name VARCHAR[255] NOT NULL UNIQUE,
    description TEXT,
    price real NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0
)
""")

name1, description1, price1, stock1 ="Product 1", "This is the first product", 29.99, 50
name2, description2, price2, stock2 ="Product 2", "This is the Second product", 12.55, 1000
name3, description3, price3, stock3 ="Product 3", "This is the Third product", 1.3, 5000
name4, description4, price4, stock4 ="Product 4", "This is the Forth product", 599.99, 10

cursor.execute("INSERT INTO product (name, description, price, stock) VALUES (?,?,?,?)",(name1,description1,price1,stock1))
cursor.execute("INSERT INTO product (name, description, price, stock) VALUES (?,?,?,?)",(name2,description2,price2,stock2))
cursor.execute("INSERT INTO product (name, description, price, stock) VALUES (?,?,?,?)",(name3,description3,price3,stock3))
cursor.execute("INSERT INTO product (name, description, price, stock) VALUES (?,?,?,?)",(name4,description4,price4,stock4))

sqlConnection.commit()