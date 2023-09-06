import logging
import os
import shutil
from azure.storage.blob import BlobServiceClient
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import rsa
import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:

    logging.info("App Started")

    TENANT_ID = os.environ.get('TENANT_ID')
    CLIENT_ID = os.environ.get('CLIENT_ID')
    CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
    KEYVAULT_NAME = os.environ.get('KEYVAULT_NAME')
    KEYVAULT_URI = f'https://{KEYVAULT_NAME}.vault.azure.net/'
    STORAGE_ACCOUNT_URL = os.environ.get('STORAGE_ACCOUNT_URL')
    ENCRYPTED_FILENAME= 'encrypted_file.txt'
    DECRYPTED_FILENAME = 'decrypted_file.txt'
    PRIVATE_KEY_NAME = 'private.pem'
    INPUT_CONTAINER_NAME = 'test'
    OUTPUT_CONTAINER_NAME = 'output'
    SECRETS_CONTAINER_NAME = 'secrets'
    LOCAL_TEMP_DIR = 'tmp'
    
    def get_storage_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI):

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
    
    def get_encrypted_file(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL, INPUT_CONTAINER_NAME, ENCRYPTED_FILENAME, LOCAL_TEMP_DIR):

        """
        Downloads the encrypted data file from ADLS to Local Storage.
        """

        #download from blob
        CONTAINER_NAME= INPUT_CONTAINER_NAME
        LOCAL_FILENAME = f'/{LOCAL_TEMP_DIR}/{ENCRYPTED_FILENAME}'
        BLOB_NAME= ENCRYPTED_FILENAME

        account_key = get_storage_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI)
        blob_service_client = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=account_key)
        blob_client = blob_service_client.get_blob_client(CONTAINER_NAME, BLOB_NAME, snapshot=None)

        with open(LOCAL_FILENAME, "wb") as my_blob:
            blob_data = blob_client.download_blob()
            blob_data.readinto(my_blob)
        my_blob.close()

    def get_decryption_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL, SECRETS_CONTAINER_NAME, PRIVATE_KEY_NAME, LOCAL_TEMP_DIR):

        """
        Downloads the PEM file to Local Storage.
        """

        CONTAINER_NAME= SECRETS_CONTAINER_NAME
        LOCAL_FILENAME = f'/{LOCAL_TEMP_DIR}/{PRIVATE_KEY_NAME}'
        BLOB_NAME= f'/keys/{PRIVATE_KEY_NAME}'

        account_key = get_storage_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI)
        blob_service_client = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=account_key)
        blob_client = blob_service_client.get_blob_client(CONTAINER_NAME, BLOB_NAME, snapshot=None)

        with open(LOCAL_FILENAME, "wb") as my_blob:
            blob_data = blob_client.download_blob()
            blob_data.readinto(my_blob)
        my_blob.close()

    def decrypt_file(ENCRYPTED_FILENAME, DECRYPTED_FILENAME, PRIVATE_KEY_NAME, LOCAL_TEMP_DIR):

        """
        Decrypts the downloaded file.
        """
        LOCAL_ENCRYPTED_FILENAME = f'/{LOCAL_TEMP_DIR}/{ENCRYPTED_FILENAME}'
        with open(LOCAL_ENCRYPTED_FILENAME, 'rb') as f:
            encrypted_data = f.read()


        # # Read private key
        LOCAL_PRIVATE_KEY_NAME = f'/{LOCAL_TEMP_DIR}/{PRIVATE_KEY_NAME}'
        with open(LOCAL_PRIVATE_KEY_NAME, 'rb') as f:
            decryption_key = rsa.PrivateKey.load_pkcs1(f.read())
    
        decrypted_data = rsa.decrypt(encrypted_data, decryption_key)

        # Write Decrypted file
        LOCAL_DECRYPTED_FILENAME = f'/{LOCAL_TEMP_DIR}/{DECRYPTED_FILENAME}'
        with open(LOCAL_DECRYPTED_FILENAME, 'w') as f:
            f.write(decrypted_data.decode())

    def upload_decrypted_file(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL, DECRYPTED_FILENAME, OUTPUT_CONTAINER_NAME, LOCAL_TEMP_DIR):

        """
        Uploads the decrypted back to ADLS to output container.
        """

        CONTAINER_NAME= OUTPUT_CONTAINER_NAME
        LOCAL_DECRYPTED_FILENAME= f'/{LOCAL_TEMP_DIR}/{DECRYPTED_FILENAME}'
        BLOB_NAME = DECRYPTED_FILENAME

        account_key = get_storage_account_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI)
        blob_service_client = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=account_key)
        blob_client = blob_service_client.get_blob_client(CONTAINER_NAME, BLOB_NAME, snapshot=None)
        with open(file=LOCAL_DECRYPTED_FILENAME, mode="rb") as data:
            blob_client.upload_blob(data, overwrite=True)

    def clean_files(LOCAL_TEMP_DIR):
    
        """
        Removes the encrypted file and PEM file from Local Storage.
        """
        shutil.rmtree(LOCAL_TEMP_DIR, ignore_errors=False, onerror=None)

    # # Uncomment below line when running outside Azure Functions
    
    # if not os.path.exists(LOCAL_TEMP_DIR):
    #     os.mkdir(LOCAL_TEMP_DIR)


    get_encrypted_file(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL, INPUT_CONTAINER_NAME, ENCRYPTED_FILENAME, LOCAL_TEMP_DIR)
    get_decryption_key(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL, SECRETS_CONTAINER_NAME, PRIVATE_KEY_NAME, LOCAL_TEMP_DIR)
    decrypt_file(ENCRYPTED_FILENAME, DECRYPTED_FILENAME, PRIVATE_KEY_NAME, LOCAL_TEMP_DIR)
    upload_decrypted_file(TENANT_ID, CLIENT_ID, CLIENT_SECRET, KEYVAULT_URI, STORAGE_ACCOUNT_URL, DECRYPTED_FILENAME, OUTPUT_CONTAINER_NAME, LOCAL_TEMP_DIR)

    # # Uncomment below line when running outside Azure Functions
    # clean_files(LOCAL_TEMP_DIR)

    return func.HttpResponse("Function Completed Successfully..!!")

