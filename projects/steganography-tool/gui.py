import tkinter as tk
from tkinter import filedialog, messagebox
from steg import (
    encode_text_in_image, decode_text_from_image,
    encode_file_in_image, decode_file_from_image
)
import os

def launch_gui():
    root = tk.Tk()
    root.title("Steganography Tool")
    root.geometry("450x400")

    def select_image():
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.bmp")])
        image_path_var.set(path)

    def select_file():
        path = filedialog.askopenfilename()
        file_path_var.set(path)

    def encode_text():
        img = image_path_var.get()
        msg = message_entry.get()
        pwd = password_entry.get()
        if not img or not msg:
            messagebox.showerror("Error", "Select image and enter message.")
            return
        out_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not out_path:
            return
        encode_text_in_image(img, out_path, msg, password=pwd if pwd else None)
        messagebox.showinfo("Success", f"Message encoded and saved to {out_path}")

    def decode_text():
        img = image_path_var.get()
        pwd = password_entry.get()
        if not img:
            messagebox.showerror("Error", "Select image to decode.")
            return
        msg = decode_text_from_image(img, password=pwd if pwd else None)
        messagebox.showinfo("Decoded Message", msg)

    def encode_file():
        img = image_path_var.get()
        file_path = file_path_var.get()
        pwd = password_entry.get()
        if not img or not file_path:
            messagebox.showerror("Error", "Select image and file to hide.")
            return
        out_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not out_path:
            return
        encode_file_in_image(img, out_path, file_path, password=pwd if pwd else None)
        messagebox.showinfo("Success", f"File hidden and saved to {out_path}")

    def decode_file():
        img = image_path_var.get()
        pwd = password_entry.get()
        if not img:
            messagebox.showerror("Error", "Select image to extract file from.")
            return
        out_dir = filedialog.askdirectory()
        if not out_dir:
            return
        result = decode_file_from_image(img, out_dir, password=pwd if pwd else None)
        messagebox.showinfo("File Extraction", result)

    image_path_var = tk.StringVar()
    file_path_var = tk.StringVar()

    tk.Label(root, text="Image:").pack(pady=5)
    tk.Entry(root, textvariable=image_path_var, width=45).pack(pady=2)
    tk.Button(root, text="Browse Image", command=select_image).pack(pady=2)

    tk.Label(root, text="Password (optional, for encryption):").pack(pady=5)
    password_entry = tk.Entry(root, width=45, show='*')
    password_entry.pack(pady=2)

    # --- Text Steganography ---
    tk.Label(root, text="Message to Hide:").pack(pady=5)
    message_entry = tk.Entry(root, width=45)
    message_entry.pack(pady=2)
    tk.Button(root, text="Encode Message", command=encode_text).pack(pady=2)
    tk.Button(root, text="Decode Message", command=decode_text).pack(pady=2)

    # --- File Steganography ---
    tk.Label(root, text="File to Hide:").pack(pady=5)
    tk.Entry(root, textvariable=file_path_var, width=45).pack(pady=2)
    tk.Button(root, text="Browse File", command=select_file).pack(pady=2)
    tk.Button(root, text="Encode File", command=encode_file).pack(pady=2)
    tk.Button(root, text="Decode File", command=decode_file).pack(pady=2)

    root.mainloop() 