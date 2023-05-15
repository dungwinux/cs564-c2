#credit to https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys


if __name__ == '__main__':
    if len(sys.argv) < 2:
        msg += './decrypt.py <amount of decrypt files named "Untitled%d.txt>\n'
        sys.stderr.write(msg)
        sys.exit(1)
    count = int(sys.argv[1])
    while True:
        try:
            name = "Untitled(%d).txt" % count
            f = open(name, 'rb')
            toBeDecrypted = f.read()
            f.close()
    
            with open("private_key.pem", 'rb') as key_file:
                private_key=serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
        
            decrypted = private_key.decrypt(
                toBeDecrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print((decrypted.decode("utf-8")))
            count-=1

        except:
            #out of files to decrypt
            break

