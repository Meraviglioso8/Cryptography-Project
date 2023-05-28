from argon2 import PasswordHasher

password = "password123"

ph = PasswordHasher()
hash = ph.hash(password)

print(hash)

try:
    ph.verify(hash, password)
    print("Password is correct")
except:
    print("Password is incorrect")