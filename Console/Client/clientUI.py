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
# SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
# find the ca cert
context.load_verify_locations(cafile=certifi.where())

# Connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(client, server_hostname= "nghiencaphesua.cloud")
client.connect(("20.187.76.92", 9999))

print("Client connected successfully")
def receive():
    while True:
        try:
            message = client.recv(1024)
#-----------------------------------HANDLE REGISTER MESSAGE -------------------------------------
            
            if message.startswith(b"FACTOR:"):
            # Received the encrypted factor, save it to file
                username = message.decode().split(':')[1].split('/')[0]
                factor = message.decode().split('(')[1].split(')')[0]
                filename = hashlib.sha256(username.encode()).hexdigest()
                with open(str(filename[:10]), "wb") as f:
                    f.write(bytes.fromhex(factor))
                print("factor saved to file. input OK for confirmation")
                
            elif message.startswith(b"Username already existed! Try again."):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Your email already been used. Try again"):
                messagebox.showinfo("Error", message.decode(0))   
            elif message.startswith(b"Register successfully!"):
                messagebox.showinfo("Announcement",message.decode())
                registration_window.destroy()
            elif message.startswith(b"Your email is not"):
                messagebox.showinfo("Error",message.decode())

#-----------------------------------HANDLE LOGIN MESSAGE --------------------------------------
                
            #start generating OTP ass username + password is valid
            elif message.startswith(b"Start"):
                username = message.decode()[5:]
                reqOTP(username)
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
            elif message.startswith(b"Login IP does not match"):
                verifycode_panel()
            elif message.startswith(b"Invalid recovery code."):
                messagebox.showinfo("Error",message.decode())
            elif message.startswith(b"Change login location"):
                messagebox.showinfo("Error",message.decode())
            
            #stop generate OTP as login successfully
            elif message.startswith(b'Input your OTP'):
                otp_panel()
            elif message.startswith(b"Invalid OTP code, you are added into suspicious table"):
                messagebox.showinfo("Error",message.decode())
                otp_window.destroy()
                login_function()

   
            elif message.startswith(b"Login complete"):
                login_window.destroy()
                messagebox.showinfo("Notification",message.decode())
            elif message.startswith(b"You are recognized as user privilege"):
                messagebox.showinfo("Notification","You are recognized as user privilege")
            elif message.startswith(b"Your role was changed by the third party"):
                messagebox.showinfo("Notification",message.decode())
                login_function()
            elif message.startswith(b"You are recognized as admin privilege"):
                messagebox.showinfo("Notification","You are recognized as admin privilege")
                admin_panel()
                
#-----------------------------------------HANDLE FORGET MESSAGE---------------------------------------
            elif message.startswith(b"Enter your new password:"):
                passwordchange_panel()
            elif message.startswith(b"Your password did not match. Please try again"):
                messagebox.showinfo("Error", message.decode())
                change_window.destroy()
            elif message.startswith(b"Password changed successfully"):
                messagebox.showinfo("Successfully change password", message.decode())
            elif message.startswith(b"Wrong recovery code! Please try again"):
                messagebox.showinfo("Error", message.decode())
                change_window.destroy()
                

#------------------------------------------HANDLE ADMIN PRIVILEGE -------------------------------------
#Change privilege
            elif message.startswith(b"Changed role to"):
                if changeprivilege_window is not None:
                    otp_window.destroy()
                messagebox.showinfo("Success", message.decode())
            elif message.startswith(b"No user found"):
                if changeprivilege_window is not None:
                    otp_window.destroy()
                messagebox.showinfo("Error", message.decode())
#Delete user
            elif b"deleted" in message:
                if delete_window is not None:
                    otp_window.destroy()
                messagebox.showinfo("Success", message.decode())
            elif b"doesn't exist" in message:
                if delete_window is not None:
                    otp_window.destroy()
                messagebox.showinfo("Error", message.decode())
#Unlock user
            elif b"unlocked" in message:
                if unlock_window is not None:
                    otp_window.destroy()
                messagebox.showinfo("Success", message.decode())
            elif b"is not in Suspected" in message:
                if unlock_window is not None:
                    otp_window.destroy()
                messagebox.showinfo("Error", message.decode())
                
#------------------------------------------------------------------------------------------------------------------
            else:
                # Received a regular message, print it to the console
                print(message.decode())

        except Exception as e:
            client.close()
            break

def reqOTP(username):
    filename = hashlib.sha256(username.encode()).hexdigest()
    f= open(str(filename[:10]), "rb")
    factor = hexlify(f.read())
    
    #generate first time
    global otp
    otp = generate_totp(factor.decode())
    filename = hashlib.sha256(username.encode()).hexdigest()
    with open(str(filename[:10]) + "_OTP", "w") as f:
        f.write(otp)


            
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

#-----------------------------------BUTTON FUNCTIONS--------------------------------
def login_function():
    client.send("/login".encode())
    login_panel()
    
def register_function():
    client.send("/register".encode())
    register_panel()
    
def forget_function():
    client.send("/forget".encode())
    forget_panel()
    
#for admin privilege    
def changeprivilege_function():
    client.send("/change".encode())
    changeprivilege_panel()
    
def delete_function():
    client.send("/delete".encode())
    delete_panel()
    
def unlock_function():
    client.send("/unlock".encode())
    unlock_panel()

#-------------------------------------------ALL REGISTRATION UI ---------------------------------
def register_panel():
    global registration_window     
    registration_window = tk.Tk()
    registration_window.geometry("400x400")
    registration_window.title("Registration")

    # Username input
    username_label = ctk.CTkLabel(registration_window, text="Username:", text_color='#000000')
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(registration_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Password input
    password_label = ctk.CTkLabel(registration_window, text="Password:", text_color='#000000')
    password_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    password_entry = ctk.CTkEntry(registration_window,corner_radius=10, show="*")
    password_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # Email input
    email_label = ctk.CTkLabel(registration_window, text="Email:", text_color='#000000')
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
    
#---------------------------------------------ALL LOGIN UI--------------------------------

def login_panel():
    global login_window       
    login_window = tk.Tk()
    login_window.geometry("400x400")
    login_window.title("Login")

    # Username input
    username_label = ctk.CTkLabel(login_window, text="Username:", text_color='#000000')
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(login_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Password input
    password_label = ctk.CTkLabel(login_window, text="Password:", text_color='#000000')
    password_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    password_entry = ctk.CTkEntry(login_window,corner_radius=10, show="*")
    password_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # login button
    login_button = ctk.CTkButton(master = login_window,corner_radius=10, command =lambda: button_2input_clicked(username_entry,password_entry), text="Login")
    login_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    login_window.mainloop()
    
def button_2input_clicked(username_entry,password_entry):
    try:
        username = username_entry.get()
        client.send(username.encode())
        password = password_entry.get()
        client.send(password.encode())
    except Exception as ex:
        messagebox.showinfo("Error", ex.message)
        
def button_1input_clicked(username_entry):
    try:
        username = username_entry.get()
        client.send(username.encode())
    except Exception as ex:
        messagebox.showinfo("Error", ex.message)



#-----------------------------------------------ALL OTP UI --------------------------------
def otp_button_clicked(otp_entry):
    try:
        otp = otp_entry.get()
        client.send(otp.encode())
        if otp_window is not None:
            otp_window.destroy()
            messagebox.showinfo("Announcement", "OTP sent successfully")
    except Exception as ex:
        messagebox.showinfo("Error", ex.message)
    
def otp_panel():
    global otp_window
    otp_window = tk.Tk()
    otp_window.geometry("200x200")
    otp_window.title("OTP")
    
    #input otp
    otp_entry = ctk.CTkEntry(otp_window, corner_radius=10)
    otp_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    otp_button = ctk.CTkButton(master = otp_window,corner_radius=10, command =lambda: otp_button_clicked(otp_entry), text="OTP")
    otp_button.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    otp_window.mainloop()

#------------------------------------------------ALL VERIFY CODE UI --------------------------------

def verifycode_panel():
    global verifycode_window
    verifycode_window = tk.Tk()
    verifycode_window.geometry("400x200")
    verifycode_window.title("Verify Code")
    
    label = ctk.CTkLabel(verifycode_window, text="Enter verification code", text_color='#000000', width=200)
    label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    
    verifycode_entry = ctk.CTkEntry(verifycode_window, corner_radius=10)
    verifycode_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    verifycode_button = ctk.CTkButton(master = verifycode_window,corner_radius=10, command =lambda: verify_clicked(verifycode_entry), text="Verify Code")
    verifycode_button.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    verifycode_window.mainloop() 
    
def verify_clicked(username_entry):
    try:
        username = username_entry.get()
        client.send(username.encode())
        if verifycode_window is not None:
            verifycode_window.destroy()
            messagebox.showinfo("Announcement", "Recovery sent successfully")
    except Exception as ex:
        messagebox.showinfo("Error", ex.message)
#-----------------------------------------------ALL FORGET UI-----------------------------------------
def forget_panel():  
    global forget_window     
    forget_window = tk.Tk()
    forget_window.geometry("400x400")
    forget_window.title("Forget")

    # Username input
    username_label = ctk.CTkLabel(forget_window, text="Username:", text_color='#000000')
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(forget_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Recovery code input
    recoverycode_label = ctk.CTkLabel(forget_window, text="Recovery Code:", text_color='#000000')
    recoverycode_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    recoverycode_entry = ctk.CTkEntry(forget_window,corner_radius=10)
    recoverycode_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # forget button
    forget_button = ctk.CTkButton(master = forget_window,corner_radius=10, command =lambda: button_2input_clicked(username_entry,recoverycode_entry), text="Forget")
    forget_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    forget_window.mainloop()

#--------------------------------------------------ALL PASSWORD CHANGE UI-----------------------------------------------

def passwordchange_panel():
    global change_window
    change_window = tk.Tk()
    change_window.geometry("400x400")
    change_window.title("New Password")

    # Username input
    pw1_label = ctk.CTkLabel(change_window, text="New password:", text_color='#000000')
    pw1_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    pw1_entry = ctk.CTkEntry(change_window, corner_radius=10)
    pw1_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Recovery code input
    pw2_label = ctk.CTkLabel(change_window, text="Confirm your password:", width = 250, text_color='#000000')
    pw2_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    pw2_entry = ctk.CTkEntry(change_window,corner_radius=10)
    pw2_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # passchange button
    change_button = ctk.CTkButton(master = change_window,corner_radius=10, command =lambda: change_clicked(pw1_entry,pw2_entry), text="Change")
    change_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    change_window.mainloop()

def change_clicked(username_entry,password_entry):
    try:
        passw = username_entry.get()
        client.send(passw.encode())
        pass2 = password_entry.get()
        client.send(pass2.encode())
        if change_window is not None:
            change_window.destroy()

    except Exception as ex:
        messagebox.showinfo("Error", ex.message)

#---------------------------------ALL UI FOR ADMIN PRIVILEGE----------------------------------------------------

def admin_panel():
    
    global admin_tk
    admin_tk = tk.Tk()
    admin_tk.geometry("400x400")
    admin_tk.title("Admin")
    
    buttonc_changeprivilege = ctk.CTkButton(master=admin_tk, corner_radius=10, command=lambda:changeprivilege_function, text = "Change privilege", width = 150)
    buttonc_changeprivilege.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

    button_delete = ctk.CTkButton(master=admin_tk, corner_radius=10, command= lambda: delete_function, text = "Delete")
    button_delete.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    button_unlock = ctk.CTkButton(master=admin_tk, corner_radius=10, command= lambda: unlock_function, text = "Unlock")
    button_unlock.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
    admin_tk.mainloop()
    
def changeprivilege_panel():
    client.send("/change".encode())
    global changeprivilege_window
    changeprivilege_window = tk.Tk()
    changeprivilege_window.geometry("400x400")
    changeprivilege_window.title("Privilege")

    # Username input
    username_label = ctk.CTkLabel(changeprivilege_window, text="Enter username to change privilege:", text_color='#000000',width = 300)
    username_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(changeprivilege_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    # Role input
    role_label = ctk.CTkLabel(changeprivilege_window, text="Enter role(admin or normal):", text_color='#000000',width = 200)
    role_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    role_entry = ctk.CTkEntry(changeprivilege_window,corner_radius=10)
    role_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # change button
    change_button = ctk.CTkButton(master = changeprivilege_window,corner_radius=10, command =lambda: button_2input_clicked(username_entry,role_entry), text="Change")
    change_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
    changeprivilege_window.mainloop()

def delete_panel():
    client.send("/delete".encode())
    global delete_window
    delete_window = tk.Tk()
    delete_window.geometry("400x200")
    delete_window.title("Delete User")

    # Username input
    username_label = ctk.CTkLabel(delete_window, text="Enter username to delete:", text_color='#000000',width=250)
    username_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(delete_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # change button
    change_button = ctk.CTkButton(master = delete_window,corner_radius=10, command =lambda: button_1input_clicked(username_entry), text="Delete")
    change_button.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
    delete_window.mainloop()
       
def unlock_panel():
    client.send("/unlock".encode())
    global unlock_window
    unlock_window = tk.Tk()
    unlock_window.geometry("400x200")
    unlock_window.title("Unlock User")

    # Username input
    username_label = ctk.CTkLabel(unlock_window, text="Enter username to unlock:",text_color='#000000', width =250)
    username_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    username_entry = ctk.CTkEntry(unlock_window, corner_radius=10)
    username_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    
    # change button
    change_button = ctk.CTkButton(master = unlock_window,corner_radius=10, command =lambda: button_1input_clicked(username_entry), text="Unlock")
    change_button.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
    unlock_window.mainloop()
    
def main():
    try:
        client.do_handshake()
        cert = client.getpeercert()
        
        #UI
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
            print("Server cert verified")
            receive_thread = threading.Thread(target=receive)
            receive_thread.start()
        else:
            print("Server cert verification failed. Close the connection.")
            client.close()
        root_tk.mainloop()
    except ssl.SSLError as e:
        print("SSL handshake error:", e)
        client.close()

if __name__ == "__main__":
    main()