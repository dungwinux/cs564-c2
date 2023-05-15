#credit to https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

if __name__ == '__main__':
    if len(sys.argv) < 3:
        msg += './uploader.py <source to file> <source to public key>\n'
        sys.stderr.write(msg)
        sys.exit(1)
    f = open(sys.argv[1], 'rb')
    toBeEncrypted = f.read()
    f.close()
    
    with open(sys.argv[2], 'rb') as key_file:
        public_key=serialization.load_pem_public_key(key_file.read(),backend=default_backend())
        
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    f = open("encrypted.txt", 'w')
    f.write(encrypted)
    f.close()


