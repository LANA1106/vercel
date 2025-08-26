from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
import base64
import os

# --- Encryption helpers ---
def derive_key(password):
    # Derive a Fernet key from the password (simple, not for production)
    # Pad/truncate password to 32 bytes, then base64 encode
    key = password.encode('utf-8')
    key = key.ljust(32, b'0')[:32]
    return base64.urlsafe_b64encode(key)

def encrypt_message(message, password):
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode('utf-8'))

def decrypt_message(token, password):
    key = derive_key(password)
    f = Fernet(key)
    try:
        return f.decrypt(token).decode('utf-8')
    except InvalidToken:
        return None

def encrypt_bytes(data, password):
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_bytes(token, password):
    key = derive_key(password)
    f = Fernet(key)
    try:
        return f.decrypt(token)
    except InvalidToken:
        return None

# --- LSB Steganography for text ---
def encode_text_in_image(input_image_path, output_image_path, message, password=None):
    if password:
        message = encrypt_message(message, password)
        # Store as base64 to keep it text
        message = base64.b64encode(message).decode('utf-8')
    image = Image.open(input_image_path)
    encoded = image.copy()
    width, height = image.size
    message += chr(0)  # Null-terminator
    data = ''.join([format(ord(i), '08b') for i in message])
    data_index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(image.getpixel((x, y)))
            for n in range(3):
                if data_index < len(data):
                    pixel[n] = pixel[n] & ~1 | int(data[data_index])
                    data_index += 1
            encoded.putpixel((x, y), tuple(pixel))
            if data_index >= len(data):
                break
        if data_index >= len(data):
            break
    encoded.save(output_image_path)

def decode_text_from_image(image_path, password=None):
    image = Image.open(image_path)
    width, height = image.size
    bits = []
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            for n in range(3):
                bits.append(str(pixel[n] & 1))
    chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]
    message = ''
    for c in chars:
        if c == chr(0):
            break
        message += c
    if password:
        try:
            # Try to decode base64 and decrypt
            encrypted = base64.b64decode(message)
            decrypted = decrypt_message(encrypted, password)
            if decrypted is None:
                return '[Decryption failed: wrong password or corrupted data]'
            return decrypted
        except Exception:
            return '[Decryption failed: not encrypted or corrupted data]'
    return message

# --- LSB Steganography for files ---
def encode_file_in_image(input_image_path, output_image_path, file_path, password=None):
    with open(file_path, 'rb') as f:
        data = f.read()
    filename = os.path.basename(file_path)
    if password:
        data = encrypt_bytes(data, password)
        filename = 'enc_' + filename
    # Store filename and data, separated by a special marker
    marker = b':::'
    payload = filename.encode('utf-8') + marker + data
    # Convert to base64 to store as text
    payload_b64 = base64.b64encode(payload).decode('utf-8')
    encode_text_in_image(input_image_path, output_image_path, payload_b64)

def decode_file_from_image(image_path, output_dir, password=None):
    payload_b64 = decode_text_from_image(image_path)
    try:
        payload = base64.b64decode(payload_b64)
        marker = b':::'
        filename, data = payload.split(marker, 1)
        filename = filename.decode('utf-8')
        if password and filename.startswith('enc_'):
            data = decrypt_bytes(data, password)
            if data is None:
                return '[Decryption failed: wrong password or corrupted data]'
            filename = filename[4:]
        out_path = os.path.join(output_dir, filename)
        with open(out_path, 'wb') as f:
            f.write(data)
        return f'File extracted and saved as {out_path}'
    except Exception as e:
        return f'[Extraction failed: {e}]' 