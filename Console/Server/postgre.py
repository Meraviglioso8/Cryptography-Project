import os
import urllib.parse as up
import psycopg2
from binascii import unhexlify
from argon2 import PasswordHasher
from cfg import AES_KEY
from Crypto.Cipher import AES
import random
from random import getrandbits

def encrypt(in_str):
    enc = AES.new(unhexlify(AES_KEY), AES.MODE_GCM)
    ciphertext, tag = enc.encrypt_and_digest(in_str.encode())
    nonce = enc.nonce
    return ciphertext.hex(), tag.hex(),nonce.hex()

def getRecoveryCode(factor32char):
    recoveryCode = ''.join(random.sample(factor32char, 6))
    return recoveryCode

def getRoles(username):
    try:
       
        cur = conn.cursor()
        cur.execute("SELECT role FROM userInfo WHERE username = %s", [username])
        result = cur.fetchall()[0][0]
    except Exception as e:
        print(e)
    
    if result is None:
        return False # user not found
    return result

def generateFactor(username):
    role = getRoles(username)
    try:
        
        cur = conn.cursor()
        cur.execute("SELECT delete_user, search_data, insert_data, update_data, delete_data FROM rolePermissions WHERE role = %s", [role])
        result = cur.fetchall()
    except Exception as e:
        print(e)

    if result:
        key = unhexlify(AES_KEY)
        permissions = {
                    'delete_user': result[0][0],
                    'search_data': result[0][1],
                    'insert_data': result[0][2],
                    'update_data': result[0][3],
                    'delete_data': result[0][4]
                }
        permissions_bin = ''.join([bin(value)[2:].zfill(1) for value in permissions.values()])
        random1 = bin(getrandbits(8))[2:]  
        random2 = bin(getrandbits(8))[2:]  
        factor = permissions_bin + random1 + random2
        enc = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = enc.encrypt_and_digest(factor.encode())
        encryptedFactor = ciphertext.hex()

        factor32char = encryptedFactor[:16] + encryptedFactor[-16:]
         # insert the factor into the database table
        cur.execute("UPDATE userInfo SET factor = %s WHERE username = %s", [factor32char, username])
        conn.commit() # commit the transaction to save the changes to the database
        cur.close()
        print(f"Factor saved to database for user {username}: {factor32char}")
        return factor32char
    else:
        print(f"No permissions found for role: {role}")
        
up.uses_netloc.append("rbzkziqg")
url = up.urlparse("postgres://rbzkziqg:rGJI2QMcTMo7C6GGrC1f1X82FqysVz2H@satao.db.elephantsql.com/rbzkziqg")
conn = None
cur = None
ph = PasswordHasher()
try:
    
    conn = psycopg2.connect(database=url.path[1:],
    user=url.username,
    password=url.password,
    host=url.hostname,
    port=url.port
    )
    cur = conn.cursor()

    cur.execute('DROP TABLE IF EXISTS rolePermissions CASCADE')
    create_script = ''' CREATE TABLE IF NOT EXISTS rolePermissions (
                            id SERIAL NOT NULL PRIMARY KEY,
                            role VARCHAR(10) NOT NULL UNIQUE,
                            delete_user INTEGER NOT NULL DEFAULT 0,
                            search_data INTEGER NOT NULL DEFAULT 0,
                            insert_data INTEGER NOT NULL DEFAULT 0,
                            update_data INTEGER NOT NULL DEFAULT 0,
                            delete_data INTEGER NOT NULL DEFAULT 0 )'''
    cur.execute(create_script)
    insert_script = 'INSERT INTO rolePermissions (role, delete_user, search_data, insert_data, update_data, delete_data) VALUES (%s ,%s ,%s ,%s ,%s ,%s)'
    insert_values = [("admin",1,1,1,1,1), ("normal",0,1,1,1,1)]
    for i in insert_values:
        cur.execute(insert_script,i)
    
    cur.execute('DROP TABLE IF EXISTS userInfo')
    create_script = ''' CREATE TABLE IF NOT EXISTS userInfo (
                            id SERIAL NOT NULL PRIMARY KEY,
                            username varchar(40) NOT NULL,
                            password varchar(140) NOT NULL,
                            email varchar(140) NOT NULL,
                            role varchar(10) REFERENCES rolePermissions(role),
                            factor varchar(140),
                            ipaddress varchar(30),
                            recoverycode varchar(140),
                            status INTEGER NOT NULL DEFAULT 0 )'''
    cur.execute(create_script)
    
    insert_script = 'INSERT INTO userInfo (username, password, email, role) VALUES (%s ,%s, %s ,%s)'
    insert_values = [("mera",ph.hash("mera"),str(encrypt("harukasociu2308@gmail.com")),"admin"), 
                     ("kizme",ph.hash("kizme"),str(encrypt("kietngo255@gmail.com")),"admin"), 
                     ("tlhung",ph.hash("tlhung"),str(encrypt("vallol@gmail.com")),"admin")]
    for i in insert_values:
        cur.execute(insert_script,i)

    factor1 = generateFactor("mera")
    factor2 = generateFactor("kizme")
    factor3 = generateFactor("tlhung")

    adm1recoverycode = getRecoveryCode(factor1)
    adm2recoverycode = getRecoveryCode(factor2)
    adm3recoverycode = getRecoveryCode(factor3)

    adminname = ["mera", "kizme", "tlhung"]
    factors = [str(encrypt(factor1)), str(encrypt(factor2)), str(encrypt(factor3))]
    recoverycodes = [ph.hash(adm1recoverycode), ph.hash(adm2recoverycode), ph.hash(adm3recoverycode)]

    for i in range(len(adminname)):
        cur.execute("UPDATE userinfo SET factor = %s, recoverycode = %s WHERE username = %s",
                    (factors[i], recoverycodes[i], adminname[i]))
    
    #suspected table
    cur.execute('drop table if exists suspiciousTable')
    create_script = '''CREATE TABLE IF NOT EXISTS suspiciousTable(
                        usernameSUSSY varchar(40),
                        emailSUSSY varchar(140) )'''
    cur.execute(create_script)
    
    #trigger for sussyTable email the same with userInfo email
    trigger_script1 = '''CREATE OR REPLACE FUNCTION update_sussy_email()
    RETURNS TRIGGER AS $$
    BEGIN
        UPDATE suspiciousTable
        SET emailSUSSY = (SELECT email FROM userInfo WHERE username = NEW.usernameSUSSY)
        WHERE usernameSUSSY = NEW.usernameSUSSY;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;'''
    cur.execute(trigger_script1)

    trigger_script2 = '''
    CREATE TRIGGER update_sussy_email_trigger
    AFTER INSERT ON suspiciousTable
    FOR EACH ROW
    EXECUTE FUNCTION update_sussy_email();
    '''
    cur.execute(trigger_script2)
    conn.commit()
    print ("DATABASE CREATED!")
    print(f"admin 1 recovery code: {adm1recoverycode}\nadmin 2 recovery code: {adm2recoverycode}\nadmin 3 recovery code: {adm3recoverycode}")
except Exception as error:
    print(error)
finally:
    if cur is not None:
        cur.close()
    if conn is not None:
        conn.close()