import socket
import ssl
import threading
import hmac
import hashlib
import struct
import time
from binascii import hexlify
from getpass import getpass
import certifi
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

#global value
otp =''
stop_threads = False
# SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
# find the ca cert
context.load_verify_locations(cafile=certifi.where())

# Connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(client, server_hostname= "nghiencaphesua.cloud")
client.connect(("20.187.76.92", 9999))
#client.connect(("localhost", 9999))

print("Client connected successfully")
def receive():
    while True:
        try:
            global message
            message = client.recv(1024)
            
#-----------------------------------HANDLE REGISTER MESSAGE -------------------------------------

            if message.startswith(b"FACTOR:"):
            # Received the encrypted factor, save it to file
                factor = message[-32:]
                username = message.decode().split(':')[1].split('/')[0]
                filename = hashlib.sha256(username.encode()).hexdigest()
                with open(str(filename[:10]), "wb") as f:
                    f.write(bytes.fromhex(factor.decode()))
                print("factor saved to file. input OK for confirmation")
            elif message.startswith(b"Username already existed! Try again."):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Your email already been used. Try again"):
                messagebox.showinfo("Error", message.decode(0))   
            elif message.startswith(b"Register successfully!"):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Your email is not"):
                messagebox.showinfo("Error",message.decode())
            
#-----------------------------------HANDLE LOGIN MESSAGE --------------------------------------

            #start generating OTP ass username + password is valid
            elif message.startswith(b"Start"):
                username = message.decode()[5:]
                log_time = int(time.time())
                thread = threading.Thread(target=reqOTP,args=(username,log_time))
                thread.start()
                print("Please open OTP file. Note that OTP only valid in a small amount of time.")
            #noti for failed login
            elif message.startswith(b"Invalid username. Please try again."):
                messagebox.showinfo("Error", message.decode())
            elif message.startswith(b"Your account has been locked. Please contact adminstrators for more information."):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Invalid Password, you are added into suspicious table"):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"User added to suspiciousTable"):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Your account has been locked."):
                messagebox.showinfo("Error",message.decode())
            
            #Handle login from unknown location
            elif message.startswith(b"Login IP does not match the stored IP address"):
                verifycode_panel()
            elif message.startswith(b"Invalid recovery code."):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Change login location"):
                messagebox.showinfo("Error",message.decode())
            
            #stop generate OTP as login successfully            
            elif message.startswith(b'Input your OTP'):
                print("Input your OTP:")
                otp_panel()
            elif message.startswith(b"Login complete"):
                global stop_threads
                stop_threads = True
                print("Login complete")
            elif message.startswith(b"You are recognized as user privilege"):
                messagebox.showinfo("Notification","You are recognized as user privilege")
            elif message.startswith(b"You are recognized as admin privilege"):
                messagebox.showinfo("Notification","You are recognized as admin privilege")
                
#-----------------------------------------HANDLE FORGET MESSAGE---------------------------------------
            elif message.startswith(b"Enter your new password:"):
                passwordchange_panel()
            elif message.startswith(b"Your password did not match. Please try again"):
                messagebox.showinfo("Error", message.decode())
            elif message.startswith(b"Password changed successfully"):
                messagebox.showinfo("Success", message.decode())
            elif message.startswith(b"Wrong recovery code! Please try again"):
                messagebox.showinfo("Error", message.decode())
            
            else:
                # Received a regular message, print it to the console
                print(message.decode())
        except Exception as e:
            client.close()
            break
def reqOTP(username,log_time):
    filename = hashlib.sha256(username.encode()).hexdigest()
    f= open(str(filename[:10]), "rb")
    factor = hexlify(f.read())
    
    #generate first time
    global otp
    otp = generate_totp(factor.decode())
    filename = hashlib.sha256(username.encode()).hexdigest()
    with open(str(filename[:10]) + "_OTP", "w") as f:
        f.write(otp)

    while True:
        global stop_threads
        #generate again after 60 secs
        if (int(time.time())- log_time == 60):
            log_time = int(time.time())
            otp = generate_totp(factor.decode())
            with open(str(filename[:10]) + "_OTP", "w") as f:
                f.write(otp)
        #stop thread when have input OTP
        if stop_threads == True:
            stop_threads = False
            
def send(message):
    while True:
        try:
            if message is None:
                message = input()
            client.send(message.encode())
        except Exception as e:
            print(e)
            client.close()
            break
        
def generate_totp(secret_key, state=0):
    current_time = int(time.time())
    time_interval = 30
    time_steps = (current_time // time_interval) + state
    time_steps_bytes = struct.pack(">Q", time_steps)
    secret_key_bytes = secret_key.encode("ascii")
    # Generate an HMAC-SHA256 hash of the time steps using the secret key
    hmac_hash = hmac.new(secret_key_bytes, time_steps_bytes, hashlib.sha3_256).digest()

    # Calculate the offset and take last 4-byte for the TOTP code
    offset = hmac_hash[-1] & 0x0F
    code_bytes = hmac_hash[offset:offset+4]
    code = struct.unpack(">I", code_bytes)[0]
    totp_code= '{0:06d}'.format((code & 0x7FFFFFFF) % 1000000)

    return totp_code

def login_function():
    client.send("/login".encode())
    login_panel()
    
def register_function():
    client.send("/register".encode())
    register_panel()
    
def forget_function():
    client.send("/forget".encode())
    forget_panel()

#registration part
def register_panel():       
    registration_window = tk.Tk()
    registration_window.geometry("400x400")
    registration_window.title("Registration")

    # Username input
    username_label = ctk.CTkLabel(registration_window, text="Username:")
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(registration_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Password input
    password_label = ctk.CTkLabel(registration_window, text="Password:")
    password_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    password_entry = ctk.CTkEntry(registration_window,corner_radius=10, show="*")
    password_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    # Email input
    email_label = ctk.CTkLabel(registration_window, text="Email:")
    email_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
    email_entry = ctk.CTkEntry(registration_window,corner_radius=10)
    email_entry.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    
    # register button
    register_button = ctk.CTkButton(master = registration_window,corner_radius=10, command =lambda: register_button_clicked(username_entry,password_entry,email_entry), text="Register")
    register_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    registration_window.mainloop()

def register_button_clicked(username_entry, password_entry, email_entry):
    try:
        username = username_entry.get()
        client.send(username.encode())
        password = password_entry.get()
        client.send(password.encode())
        email = email_entry.get()
        client.send(email.encode())
    except Exception as  ex:
        messagebox.showinfo("Error", ex.message)       
    
#login part
def login_panel():       
    login_window = tk.Tk()
    login_window.geometry("400x400")
    login_window.title("Login")

    # Username input
    username_label = ctk.CTkLabel(login_window, text="Username:")
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(login_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Password input
    password_label = ctk.CTkLabel(login_window, text="Password:")
    password_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    password_entry = ctk.CTkEntry(login_window,corner_radius=10, show="*")
    password_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # register button
    login_button = ctk.CTkButton(master = login_window,corner_radius=10, command =lambda: login_button_clicked(username_entry,password_entry), text="Login")
    login_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    login_window.mainloop()
    
def login_button_clicked(username_entry,password_entry):
    try:
        username = username_entry.get()
        client.send(username.encode())
        password = password_entry.get()
        client.send(password.encode())
    except Exception as ex:
        messagebox.showinfo("Error", ex.message)

def otp_button_clicked(otp_entry):
    otp = otp_entry.get()
    client.send(otp.encode())
    
def otp_panel():
    otp_window = tk.Tk()
    otp_window.geometry("200x200")
    otp_window.title("OTP")
    
    otp_entry = ctk.CTkEntry(otp_window, corner_radius=10)
    otp_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    otp_button = ctk.CTkButton(master = otp_window,corner_radius=10, command =lambda: otp_button_clicked(otp_entry), text="OTP")
    otp_button.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    otp_window.mainloop()
def verifycode_panel():
    verifycode_window = tk.Tk()
    verifycode_window.geometry("200x200")
    verifycode_window.title("Verify Code")
    
    label = ctk.CTkLabel(verifycode_window, text="Enter verification code")
    label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
        
    verifycode_entry = ctk.CTkEntry(verifycode_window, corner_radius=10)
    verifycode_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    verifycode_button = ctk.CTkButton(master = verifycode_window,corner_radius=10, command =lambda: otp_button_clicked(verifycode_entry), text="Verify Code")
    verifycode_button.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    verifycode_window.mainloop() 
    
#Forget part
def forget_panel():       
    forget_window = tk.Tk()
    forget_window.geometry("400x400")
    forget_window.title("Forget")

    # Username input
    username_label = ctk.CTkLabel(forget_window, text="Username:")
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(forget_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Recovery code input
    recoverycode_label = ctk.CTkLabel(forget_window, text="Recovery Code:")
    recoverycode_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    recoverycode_entry = ctk.CTkEntry(forget_window,corner_radius=10)
    recoverycode_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # register button
    forget_button = ctk.CTkButton(master = forget_window,corner_radius=10, command =lambda: login_button_clicked(username_entry,recoverycode_entry), text="Forget")
    forget_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    forget_window.mainloop()

def passwordchange_panel():
    change_window = tk.Tk()
    change_window.geometry("400x400")
    change_window.title("New Password")

    # Username input
    pw1_label = ctk.CTkLabel(change_window, text="New password:")
    pw1_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    pw1_entry = ctk.CTkEntry(change_window, corner_radius=10)
    pw1_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Recovery code input
    pw2_label = ctk.CTkLabel(change_window, text="Confirm your password:")
    pw2_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    pw2_entry = ctk.CTkEntry(change_window,corner_radius=10)
    pw2_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # register button
    change_button = ctk.CTkButton(master = change_window,corner_radius=10, command =lambda: login_button_clicked(pw1_entry,pw2_entry), text="Change")
    change_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    change_window.mainloop()
    
def main():
    try:
        client.do_handshake()
        cert = client.getpeercert()

        root_tk = tk.Tk()
        root_tk.geometry("400x400")
        root_tk.title("Client")
        
        button_register = ctk.CTkButton(master=root_tk, corner_radius=10, command=register_function, text = "Register")
        button_register.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        button_login = ctk.CTkButton(master=root_tk, corner_radius=10, command=login_function, text = "Login")
        button_login.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        button_forget = ctk.CTkButton(master=root_tk, corner_radius=10, command=forget_function, text = "Forget")
        button_forget.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
        
        # check the cert if it is CA, not CA close client
        if cert:
            messagebox.showinfo("Server", "Server cert verified")
            
            receive_thread = threading.Thread(target=receive)
            receive_thread.start()
            send_thread = threading.Thread(target=send)
            send_thread.start()

        else:
            print("Server cert verification failed. Close the connection.")
            client.close()
        
        root_tk.mainloop()
        
    except ssl.SSLError as e:
        print("SSL handshake error:", e)
        client.close()

if __name__ == "__main__":
    main()


