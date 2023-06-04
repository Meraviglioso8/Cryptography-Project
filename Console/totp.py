import hmac
import hashlib
import struct
import time
import os

def generate_totp(secret_key_file):
    with open(secret_key_file, "r") as f:
        secret_key = f.read().strip()

    current_time = int(time.time())
    time_interval = 30
    time_steps = current_time // time_interval
    time_steps_bytes = struct.pack(">Q", time_steps)
    secret_key_bytes = secret_key.encode("ascii")
    
    # Generate an HMAC-SHA1 hash of the time steps using the secret key
    hmac_hash = hmac.new(secret_key_bytes, time_steps_bytes, hashlib.sha1).digest()

    # Calculate the offset and take last 4-byte for the TOTP code
    offset = hmac_hash[-1] & 0x0F
    code_bytes = hmac_hash[offset:offset+4]
    code = struct.unpack(">I", code_bytes)[0]
    totp_code= '{0:06d}'.format((code & 0x7FFFFFFF) % 1000000)

    return totp_code

# Specify the file name containing the secret key
script_dir = os.path.dirname(os.path.abspath(__file__))

# Specify the file name containing the secret key
secret_key_file = os.path.join(script_dir, "factor")

# Generate the current TOTP code
totp_code = generate_totp(secret_key_file)
print("Secret key file:", secret_key_file)
print("Current TOTP code:", totp_code)

# Wait 30 seconds to generate a new TOTP code
time.sleep(30)
new_totp_code = generate_totp(secret_key_file)

print("New TOTP code:", new_totp_code)