import psycopg2
import urllib.parse as urlparse

def check_database_values():
    try:
        url = urlparse.urlparse("postgres://rslgnkrk:KlTouCgQoGMPRngRKf8ddlBAI0FaL9_j@satao.db.elephantsql.com/rslgnkrk")  
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
    except Exception as error:
        print("Error connecting to the database:", error)

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM suspiciousTable") 
        rows = cursor.fetchall()
        for row in rows:
            print(row)
    except Exception as error:
        print("Error executing SQL query:", error)
    finally:
        if cursor:
            cursor.close()

    if conn:
        conn.close()



def main():    
    check_database_values()

if __name__ == "__main__":
    main()