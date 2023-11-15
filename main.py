import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
import io
import base64

# Generate a random key
def generate_key():
    return os.urandom(16)

# Encrypt using AES-128 in counter mode
def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)

# Image to Bytes
def image_to_bytes(image_path):
    with Image.open(image_path) as img:
        with io.BytesIO() as byte_arr:
            img.save(byte_arr, format=img.format)
            return byte_arr.getvalue()

# Bytes to Image
def bytes_to_image(byte_data, output_path):
    with open(output_path, 'wb') as f:
        f.write(byte_data)

# Placeholder function for compute_cover_set
def compute_cover_set(non_revoked_devices, total_devices):
    # Placeholder logic - here you'd implement the actual computation
    return list(non_revoked_devices)[:2]  # Just an example, returns first two devices

# Encrypt content based on the revoked devices
def encrypt_with_revocation(image_path, revoked_devices, total_devices):
    root_key = generate_key()
    content_key = generate_key()

    # Encrypt content key with root key
    encrypted_content_key = encrypt(root_key, content_key)[1]

    # Determine cover set of non-revoked devices
    non_revoked_devices = set(range(1, total_devices + 1)) - set(revoked_devices)
    cover_set = compute_cover_set(non_revoked_devices, total_devices)

    # Compute encryption keys for the cover set
    keys_for_cover_set = {node: generate_key() for node in cover_set}
    encrypted_keys = [encrypt(keys_for_cover_set[node], content_key)[1] for node in cover_set]

    # Convert the image to bytes and encrypt
    image_bytes = image_to_bytes(image_path)
    encrypted_image_iv, encrypted_image = encrypt(root_key, image_bytes)

    return {
        "encrypted_content": encrypted_image,
        "encrypted_content_iv": encrypted_image_iv,
        "encrypted_content_key": encrypted_content_key,
        "encrypted_keys_for_cover_set": encrypted_keys
    }

# Decrypt the encrypted image
def decrypt_image(encrypted_data, output_path):
    root_key = generate_key()

    # Decrypt the image
    decrypted_image = decrypt(root_key, encrypted_data['encrypted_content_iv'], encrypted_data['encrypted_content'])

    # Save the decrypted image
    bytes_to_image(decrypted_image, output_path)

# Decrypt using AES-128 in counter mode
def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Example usage
image_path = '/Users/nikagongadze/Documents/Projects/Gaxs_VehicleDet/Gaxs_VehicleDet/wwwroot/img/Baros.jpg'  # Replace with your image path
output_path = 'decrypted_image.jpg'
revoked_devices = {3, 7}  # Devices to revoke
total_devices = 8  # Total number of devices

encrypted_data = encrypt_with_revocation(image_path, revoked_devices, total_devices)

# Save the encrypted image to a file
with open('encrypted_image.bin', 'wb') as f:
    f.write(encrypted_data['encrypted_content'])

# Decryption of the image
decrypted_data = {
    'encrypted_content': open('encrypted_image.bin', 'rb').read(),
    'encrypted_content_iv': encrypted_data['encrypted_content_iv']
}

decrypt_image(decrypted_data, output_path)

print("Image encryption and decryption completed.")
