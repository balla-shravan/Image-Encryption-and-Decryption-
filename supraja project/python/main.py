import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import webbrowser
from PIL import Image, ImageTk

def generate_key():
    return Fernet.generate_key()

def write_key_to_file(key, filename="key.txt"):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def load_key_from_file(filename="key.txt"):
    try:
        with open(filename, "rb") as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        print(f"Key file '{filename}' not found.")
        return None

def encrypt_image(file_path, key):
    try:
        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            data = file.read()

        encrypted_data = fernet.encrypt(data)

        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed for {file_path}: {str(e)}")

def decrypt_image(file_path, key):
    try:
        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(file_path, 'wb') as file:
            file.write(decrypted_data)

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed for {file_path}: {str(e)}")

def encrypt_process():
    image_path = filedialog.askopenfilename(title="Select an image for encryption")

    if image_path:
        receiver_email = simpledialog.askstring("Receiver Email", "Enter the recipient's email:")
        if receiver_email:
            key = generate_key()
            write_key_to_file(key)

            encrypt_image(image_path, key)

            messagebox.showinfo("Info", "Image encrypted successfully.")

            send_key_email(receiver_email, key)

def decrypt_process():
    image_path = filedialog.askopenfilename(title="Select an image for decryption")

    if image_path:
        password = simpledialog.askstring("Password", "Enter the password for decryption:")
        if password:
            key = load_key_from_file()
            if key:
                decrypt_image(image_path, key)
                messagebox.showinfo("Info", "Image decrypted successfully.")
            else:
                messagebox.showerror("Error", "Key not found. Cannot decrypt.")

def send_key_email(receiver_email, key):
    sender_email = "bethimeghanareddymeghana@gmail.com"
    subject = "The Key for Encrypted Image"
    message = f"The Key for Encrypted Image is:\n{key}"

    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        smtp_username = "bethimeghanareddymeghana@gmail.com"
        smtp_password = "your_email_password"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        import ssl
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

        messagebox.showinfo("Info", "Key sent successfully.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to send key: {str(e)}")

def open_details_page():
    html_page_path = "index.html"
    webbrowser.open(html_page_path)

def set_background(frame):
    # Set background color to black
    frame.configure(bg="black")

    # Image Encryption label
    encryption_label = tk.Label(frame, text="Image Encryption !!!", font=("bold", 25), bg="black", fg="yellow")
    encryption_label.pack(pady=20)

    # Load the logo image using Pillow
    logo_image = Image.open("logo.jpg")

    # Calculate the desired width (25% of screen width)
    screen_width = frame.winfo_screenwidth()
    desired_width = int(screen_width * 0.25)

    # Resize the image while maintaining the aspect ratio
    original_width, original_height = logo_image.size
    desired_height = int(original_height * (desired_width / original_width))
    logo_image = logo_image.resize((desired_width, desired_height), Image.Resampling.LANCZOS)

    logo_image = ImageTk.PhotoImage(logo_image)
    logo_label = tk.Label(frame, image=logo_image, bg="black")
    logo_label.image = logo_image
    logo_label.pack(pady=10)

    # Project Info button
    details_button = tk.Button(frame, text="Project Info", command=open_details_page, bg="yellow", fg="black")
    details_button.pack(pady=10)

    # Encrypt Image button
    encrypt_button = tk.Button(frame, text="Encrypt Image", command=encrypt_process, bg="yellow", fg="black")
    encrypt_button.pack(pady=10)

    # Decrypt Image button
    decrypt_button = tk.Button(frame, text="Decrypt Image", command=decrypt_process, bg="yellow", fg="black")
    decrypt_button.pack(pady=10)

root = tk.Tk()
root.title("Image Encrypter")
root.configure(bg="black")  # Set background color to black

# Frame for Encrypt and Decrypt buttons
frame = tk.Frame(root, bg="black", padx=10, pady=10)
frame.pack(pady=20)

# Set background with image and place buttons in a vertical layout
set_background(frame)

root.mainloop()
