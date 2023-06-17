import os
import urllib.parse as up
import psycopg2
import socket
import threading
from datetime import datetime
from binascii import unhexlify
import hmac
import hashlib
import struct
import time
import ssl
from random import getrandbits
from Crypto.Cipher import AES
from argon2 import PasswordHasher
import smtplib
import random
import re
import ast
from contextlib import redirect_stdout
import io
from subprocess import *

up.uses_netloc.append('rslgnkrk')
url = up.urlparse("postgres://rbzkziqg:rGJI2QMcTMo7C6GGrC1f1X82FqysVz2H@satao.db.elephantsql.com/rbzkziqg")
conn = None
cur = None
tempOTP =''

def encrypt(in_str):
    enc = AES.new(unhexlify(getAES_KEY()), AES.MODE_GCM)
    ciphertext, tag = enc.encrypt_and_digest(in_str.encode())
    nonce = enc.nonce
    return ciphertext.hex(), tag.hex(),nonce.hex()

#decrypt function
def decrypt (in_str,tag,nonce):
    in_str = unhexlify(in_str)
    decrypt_cipher = AES.new(unhexlify(getAES_KEY()), AES.MODE_GCM,nonce=unhexlify(nonce))
    plain_text = decrypt_cipher.decrypt_and_verify(in_str, unhexlify(tag))
    return plain_text.decode()

def getDecryptData(get_data):
    get_data = decrypt(get_data[0],get_data[1],get_data[2])
    return get_data

def getAES_KEY():
     return '9A1C95B959B9B67EEF032BA0FD0ABC22'
#connect database
try:
        conn = psycopg2.connect(database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
        )
except Exception as error:
        print(error)
cur = conn.cursor()
def getRoles(username):
    result=None
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
        permissions = {
                    'delete_user': result[0][0],
                    'search_data': result[0][1],
                    'insert_data': result[0][2],
                    'update_data': result[0][3],
                    'delete_data': result[0][4]
                }
        permissions_bin = ''.join([bin(value)[2:].zfill(1) for value in permissions.values()])
        factor = permissions_bin + bin(getrandbits(8))[2:] + bin(getrandbits(8))[2:]
        print(factor)
        enc = AES.new(unhexlify(getAES_KEY()), AES.MODE_CTR)
        ciphertext = enc.encrypt(factor.encode())
        nonce = enc.nonce
        return ciphertext.hex(), nonce.hex()
    else:
        print(f"No permissions found for role: {role}")

def decryptFactor(in_str,nonce):
     in_str = unhexlify(in_str)
     decrypt_cipher = AES.new(unhexlify(getAES_KEY()), AES.MODE_CTR,nonce=nonce)
     return decrypt_cipher.decrypt(in_str).decode()

def getPermission(role):
    cur.execute("SELECT delete_user, search_data, insert_data, update_data, delete_data FROM rolePermissions WHERE role = %s", [role])
    result = cur.fetchall()
    permissions = {
                    'delete_user': result[0][0],
                    'search_data': result[0][1],
                    'insert_data': result[0][2],
                    'update_data': result[0][3],
                    'delete_data': result[0][4]
                }
    return''.join([bin(value)[2:].zfill(1) for value in permissions.values()])

factor = generateFactor('mera')
haha = "FACTOR:11111101011110111110"
print(haha[7:])
encfactor = str(encrypt(str(factor)))
print("ENC FACTOR: ",encfactor)
cur.execute("UPDATE userInfo SET factor = %s WHERE username = %s", [encfactor,'mera'])
factor = getDecryptData(ast.literal_eval(encfactor))
encfactor = ast.literal_eval(encfactor)
print ("GET CIPHERTEXT: ",(ast.literal_eval(getDecryptData(encfactor)))[1])
print(getPermission('normal'))

cur.execute("SELECT factor FROM userInfo WHERE username = %s", ['mera'])
result = cur.fetchone()
message = "FACTOR:hoho/(7309374fc2ec4b7bf089d33824e54b29f44d)"
username = message.split(':')[1].split('/')[0]
factor = message.split('(')[1].split(')')[0]
print(username)
print(factor)