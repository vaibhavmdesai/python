import os
from azure.storage.blob import BlobServiceClient
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import rsa

def get_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI):

    """
    Gets the storage account key from the Azure Key Vault.
    """

    _credential = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )

    _sc = SecretClient(vault_url=KEYVAULT_URI, credential=_credential)
    storage_account_key = _sc.get_secret('storage-account-key').value

    return storage_account_key

def get_encrypted_file(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL):

    """
    Downloads the encrypted data file from ADLS to Local Storage.
    """

    #download from blob
    CONTAINERNAME= 'test'
    BLOBNAME= 'encrypted_file.txt'

    account_key = get_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI)
    blob_service_client_instance = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=account_key)
    blob_client_instance = blob_service_client_instance.get_blob_client(CONTAINERNAME, BLOBNAME, snapshot=None)

    with open(BLOBNAME, "wb") as my_blob:
        blob_data = blob_client_instance.download_blob()
        blob_data.readinto(my_blob)
    my_blob.close()


def get_decryption_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL):

    """
    Downloads the PEM file to Local Storage.
    """

    CONTAINERNAME= 'secrets'
    BLOBNAME= '/keys/private.pem'

    account_key = get_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI)
    blob_service_client_instance = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=account_key)
    blob_client_instance = blob_service_client_instance.get_blob_client(CONTAINERNAME, BLOBNAME, snapshot=None)

    with open('private.pem', "wb") as my_blob:
        blob_data = blob_client_instance.download_blob()
        blob_data.readinto(my_blob)
    my_blob.close()


def decrypt_file(LOCALFILENAME):

    """
    Decrypts the downloaded file.
    """

    with open(LOCALFILENAME, 'rb') as f:
        encrypted_data = f.read()


    # # Read private key
    with open('private.pem', 'rb') as f:
        decryption_key = rsa.PrivateKey.load_pkcs1(f.read())
   
    decrypted_data = rsa.decrypt(encrypted_data, decryption_key)

    # Write Decrypted file
    with open('decrypted_file.txt', 'w') as f:
        f.write(decrypted_data.decode())

def clean_files(LOCALFILENAME):
    
    """
    Removes the encrypted file and PEM file from Local Storage.
    """
    os.remove(LOCALFILENAME)
    os.remove('private.pem')

def main():

    TENANT_ID = os.environ.get('TENANT_ID')
    CLIENT_ID = os.environ.get('CLIENT_ID')
    CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
    KEYVAULT_NAME = os.environ.get('KEYVAULT_NAME')
    KEYVAULT_URI = f'https://{KEYVAULT_NAME}.vault.azure.net/'
    STORAGE_ACCOUNT_URL = os.environ.get('STORAGE_ACCOUNT_URL')
    LOCALFILENAME= 'encrypted_file.txt'


    get_encrypted_file(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL)
    get_decryption_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL)
    decrypt_file(LOCALFILENAME)
    clean_files(LOCALFILENAME)

main()

