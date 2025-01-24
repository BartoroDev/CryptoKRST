import argparse
import os
import hashlib
import requests
import time
import json
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import randrange_from_seed__trytryagain
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from pow import Transaction

def make_asymetric_key(seed):
    secexp = randrange_from_seed__trytryagain(seed, SECP256k1.order)
    return SigningKey.from_secret_exponent(secexp, curve=SECP256k1)

def get_keys_from_seed(seed: str, num: int) -> dict:
    lock = dict()
    for i in range(num):
        s_key = make_asymetric_key(f"{i}:"+seed)
        v_key = s_key.verifying_key
        lock[i]={
        "private_key": s_key.to_string().hex(),
        "public_key": v_key.to_string().hex()
        }
    
    return lock

def get_public_key_from_pk(private_key_hex: str) -> str:
    private_key_bytes = bytes.fromhex(private_key_hex)
    s_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    v_key = s_key.verifying_key
    return v_key.to_string().hex()

def p2pk_script(public_key):
    lenght = 32 #TODO:lenght of script
    print(f"header {lenght}") #magic bytes
    print("pk:" + public_key) #pub key
    print("op: checksig")   #opcode
    pass

def sign_data(seed: str, data: str) -> dict:
    keys=get_keys_from_seed(seed, 1) #TODO:fix it later
    """Sign the given data using the private key."""
    private_key_bytes = bytes.fromhex(keys[0]["private_key"])
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    signature = sk.sign(data.encode()).hex()
    return {
        "signature": signature,
        "public_key": keys[0]["public_key"]
    }

def sign_with_key(private_key_hex: str, data: str) -> dict:
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    signature = sk.sign(data.encode()).hex()
    vk = sk.get_verifying_key()
    public_key_hex = vk.to_string().hex()
    return {
        "signature": signature,
        "public_key": public_key_hex
    }

#TODO: save- keypairs for each of your addresses
#transactions done from/to your addresses
#to an ecrypted file
def derive_symetric_key(password: str) -> bytes:
    kdf = Scrypt(
        salt=b'',  # Używamy pustej soli
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # Zwracamy nonce wraz z szyfrogramem

def decrypt_data(key: bytes, data: bytes) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

def save_to_file(filename: str, password: str, data: dict):
    key = derive_symetric_key(password)
    plaintext = json.dumps(data).encode()
    ciphertext = encrypt_data(key, plaintext)
    with open(filename, 'wb') as f:
        f.write(ciphertext)  

def load_from_file(filename: str, password: str) -> dict:
    with open(filename, 'rb') as f:
        file_data = f.read()
    key = derive_symetric_key(password)
    plaintext = decrypt_data(key, file_data)
    data = json.loads(plaintext.decode())
    return data

def mock_transaction() -> list:
    result =  [
    {
        'txid': 'transakcja_1',
        'inputs': [
            {'address': 'adres_1', 'amount': -50},
            {'address': 'adres_2', 'amount': -30},
        ],
        'outputs': [
            {'address': 'adres_3', 'amount': 80},
        ],
        'address_changes': {
            'adres_1': -50,
            'adres_2': -30,
            'adres_3': 80,
        }
    },
    {
        'txid': 'transakcja_2',
        'inputs': [
            {'address': 'adres_3', 'amount': -20},
        ],
        'outputs': [
            {'address': 'adres_1', 'amount': 20},
        ],
        'address_changes': {
            'adres_3': -20,
            'adres_1': 20,
        }
    },
    ]
    return result


def main():
    parser = argparse.ArgumentParser(description="en")
    parser.add_argument("--seed", type=str, help="Specify a recovery string for a wallet", default='0')
    parser.add_argument("--number", type=int, help="Specify number of keys to access", default=1)
    parser.add_argument("--f", type=str, help="open file", default=None)
    parser.add_argument("--p", type=str, help="password", default="")
    parser.add_argument("--t", type=str, help="transaction url", default="")
    parser.add_argument("--a", type=int, help="transaction ammount", default=0)
    args = parser.parse_args()

    if args.t != "":
        sender = get_public_key_from_pk('7e01f59d8d4793e62ab05b9cd9c3689fb62cbfd86280f677faf41c40181ea2b7')
        recipient = get_public_key_from_pk('6c6cd441c23ef178270b457bf8dae9535f84b505894ccce8c13e627049be8e3d')
        tx1 = Transaction(sender=sender, recipient=recipient, amount=args.a)
        tx1.signature = sign_with_key('7e01f59d8d4793e62ab05b9cd9c3689fb62cbfd86280f677faf41c40181ea2b7', tx1.hash)["signature"]
        response = requests.post(args.t, json=tx1.as_dict())
        print("Status Code:", response.status_code)
        print("Response Body:", response.text)
        return #todo: curl to post signed transaction
   
    wallet = {
        'keypairs': None,
        'transaction_cache': mock_transaction()
    }
    if args.f != None:
        wallet = load_from_file(args.f, args.p)
    
    elif args.seed == '0':
        seed ="my_secure_seed" # Generate a random 32-byte seed
        print(f"Generated seed: {seed}")
        wallet['keypairs'] = get_keys_from_seed(seed, args.number)
    else:
        seed = args.seed
        print(f"Using provided seed")
        wallet['keypairs'] = get_keys_from_seed(seed, args.number)
    
    # Generate ECDSA keypair based on the seed
    
    for key in wallet['keypairs'].keys():        
        # Display  (keypairs)
        print(f"ECDSA keypair number: {key}")
        print(f"Master Private Key: {wallet['keypairs'][key]['private_key']}")
        print(f"Master Public Key: {wallet['keypairs'][key]['public_key']}")
    
    timestr = time.strftime("%H%M%S.dat")
    data_to_save = {
        'keypairs': wallet['keypairs'],
        'transaction_cache': mock_transaction()
    }
    save_to_file(timestr, args.p, data_to_save)
    #TODO:implement api connection and user transaction cli

if __name__ == "__main__":
    main()
