import rsa
import base64


public_key, private_key = rsa.newkeys(2048)

# Create public key
with open('public.pem', 'wb') as f:
    f.write(public_key.save_pkcs1('PEM'))


# Create private key
with open('private.pem', 'wb') as f:
    f.write(private_key.save_pkcs1('PEM'))

# Read public key
with open('public.pem', 'rb') as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

# Read private key
with open('private.pem', 'rb') as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())


# Read the file to encrypt
with open('file_to_encrypt.txt', 'r') as f:
    data = f.read()

encrypted_data = rsa.encrypt(data.encode(), public_key)


# Write Encrypted file
with open('encrypted_file.txt', 'wb') as f:
    f.write(encrypted_data)


# Decrypt file
with open('encrypted_file.txt', 'rb') as f:
    encrypted_data = f.read()


# print(encrypted_data)
decrypted_data = rsa.decrypt(encrypted_data, private_key)


# Write Decrypted file
with open('decrypted_file.txt', 'w') as f:
    f.write(decrypted_data.decode())


