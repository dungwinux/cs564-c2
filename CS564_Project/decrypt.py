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
        msg += './uploader.py <source to file> <source to private key>\n'
        sys.stderr.write(msg)
        sys.exit(1)
    f = open(sys.argv[1], 'rb')
    toBeDecrypted = f.read()
    f.close()
    
    with open(sys.argv[2], 'rb') as key_file:
        private_key=serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
        
       
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    f = open("decrypted.txt", 'w')
    f.write(decrypted)
    f.close()


