import hmac
import hashlib
import struct
import time

def generate_totp(secret_key):
    current_time = int(time.time())
    time_interval = 30
    time_steps = current_time // time_interval
    time_steps_bytes = struct.pack(">Q", time_steps)

    # Decode the secret key from base32 to bytes
    secret_key_bytes = secret_key.encode("ascii")
    # Generate an HMAC-SHA1 hash of the time steps using the secret key
    hmac_hash = hmac.new(secret_key_bytes, time_steps_bytes, hashlib.sha1).digest()

    # Calculate the offset and take last 4-byte for the TOTP code
    offset = hmac_hash[-1] & 0x0F
    code_bytes = hmac_hash[offset:offset+4]
    code = struct.unpack(">I", code_bytes)[0]
    totp_code= '{0:06d}'.format((code & 0x7FFFFFFF) % 1000000)

    return totp_code

# Generate a random secret key
secret_key = "JBSWY3DPEHPK3PXP"

# Generate the current TOTP code
totp_code = generate_totp(secret_key)
print("Secret key:", secret_key)
print("Current TOTP code:", totp_code)

# Wait 30 seconds to generate a new TOTP code
time.sleep(30)
new_totp_code = generate_totp(secret_key)


print("New TOTP code:", new_totp_code)