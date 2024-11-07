import base64
import json
import time
from collections import defaultdict

import rsa
import _sha1
import secrets
import os
import csv

from Crypto.PublicKey import RSA

import algorithms.aes as aes
import frontend

users = {}
public_key_rings = {}
private_key_rings = {}
public_key_rings_current_user = {}


def number_to_hexabytes(number):
    converter = "0123456789abcdef"
    string = ""
    mask = 0xF
    while number > 0:
        string += converter[number & mask]
        number >>= 4
    return string[::-1]


def hexabytes_to_number(string):
    converter = "0123456789abcdef"
    number = 0
    for c in string:
        number <<= 4
        number |= converter.index(c)
    return number


def encrypt_private_key(value, key):
    if len(key) < 16:
        for i in range(16 - len(key)):
            key += key[len(key) - i - 1]
    key = key[0:16]
    key = [[ord(c) for c in key[i:i + 4]] for i in range(0, len(key), 4)]
    ciphertext = ""
    plaintext = number_to_hexabytes(value)
    padding = 0
    if len(plaintext) % 16 != 0:
        padding = 16 - len(plaintext) % 16
        plaintext += "0" * padding
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        chunk = [[ord(c) for c in chunk[i:i + 4]] for i in range(0, len(chunk), 4)]
        res = aes.aes_encrypt(chunk, key)
        res = [[chr(j) for j in i] for i in res]
        res = "".join(["".join(i) for i in res])
        ciphertext += res
    return ciphertext, padding


def decrypt_private_key(ciphertext, key, padding):
    if len(key) < 16:
        for i in range(16 - len(key)):
            key += key[len(key) - i - 1]
    key = key[0:16]
    key = [[ord(c) for c in key[i:i + 4]] for i in range(0, len(key), 4)]
    plaintext = ""
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        chunk = [[ord(j) for j in chunk[i:i + 4]] for i in range(0, len(chunk), 4)]
        res = aes.aes_decrypt(chunk, key)
        res = [[chr(j) for j in i] for i in res]
        res = "".join(["".join(i) for i in res])
        plaintext += res
    plaintext = plaintext[0:len(plaintext) - padding]
    return hexabytes_to_number(plaintext)


class PrivateEntrance:
    def __init__(self, timestamp, n, e, en_private_key, username, password, salt, d, padding):
        self.timestamp = timestamp
        self.keyid = n & 0xFFFFFFFFFFFFFFFF
        self.n = n
        self.public_key = e
        self.private_key = en_private_key
        self.username = username
        self.password = password
        self.salt = salt
        self.d = d
        self.padding = padding


class PublicEntrance:
    def __init__(self, timestamp, public_key, username):
        self.timestamp = timestamp
        self.keyid = public_key.n & 0xFFFFFFFFFFFFFFFF
        self.public_key = public_key
        self.username = username


def check_password(keyid, username, password):
    private_entrance = private_key_rings[username][keyid]
    a = (private_entrance.password == _sha1.sha1((password + private_entrance.salt).encode('utf-8')).hexdigest())
    return a


def create_user(username):
    if username in users:
        raise ValueError("User already exists")
    public_key_rings[username] = {}
    private_key_rings[username] = {}
    users[username] = 0
    os.mkdir(f"./users/user_{username}")
    with(open(f"./users/user_{username}/public_keys.csv", "w", encoding='utf-8')) as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'Key ID', 'Public Key N', 'Public Key E', 'Username'])
    save_to_files()


def create_key_pair(username, bits, password):
    public_key, private_key = rsa.newkeys(bits)
    timestamp = time.time()
    salt = secrets.token_hex(16)
    e = public_key.e
    n = public_key.n
    en_private_key, padding = encrypt_private_key(private_key.d, password)
    password = _sha1.sha1((password + salt).encode('utf-8')).hexdigest()
    private_entrance = PrivateEntrance(timestamp, n, e, en_private_key, username, password, salt,
                                       private_key.d, padding)
    if username in private_key_rings:
        private_key_rings[username][private_entrance.keyid] = private_entrance
    else:
        raise ValueError("User does not exist")
    if username in public_key_rings:
        public_key_rings[username][private_entrance.keyid] = PublicEntrance(timestamp, public_key, username)
    else:
        raise ValueError("User does not exist")
    save_to_files()


def delete_key_pair(username, keyid):
    # Check if the user exists in private_key_rings
    if username in private_key_rings:
        # Check if the keyid exists in private_key_rings for the user
        if keyid in private_key_rings[username]:
            # Delete from private_key_rings dictionary
            del private_key_rings[username][keyid]
        else:
            print(f"Key ID '{keyid}' not found in private key rings for user '{username}'")
    else:
        print(f"User '{username}' does not exist or has no private key rings")

    # Check if the user exists in public_key_rings
    if username in public_key_rings:
        # Check if the keyid exists in public_key_rings for the user
        if keyid in public_key_rings[username]:
            # Delete from public_key_rings dictionary
            del public_key_rings[username][keyid]
        else:
            print(f"Key ID '{keyid}' not found in public key rings for user '{username}'")
    else:
        print(f"User '{username}' does not exist or has no public key rings")

    # Save the updated rings to files
    save_to_files()


def get_user_key_ids(username):
    if username not in private_key_rings:
        return []
    return [entrance for entrance in public_key_rings[username].keys()]


def find_public_key(keyid):
    for username in public_key_rings:
        if keyid in public_key_rings[username]:
            return public_key_rings[username][keyid].public_key
    return None


def get_private_key(keyid, username, password):
    if not check_password(keyid, username, password):
        return None
    return decrypt_private_key(private_key_rings[username][keyid].private_key, password,
                               private_key_rings[username][keyid].padding), private_key_rings[username][keyid].n


def save_to_files():
    for user in users:
        with open(f"users/user_{user}/private_keys.csv", "w", encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(
                ["timestamp", "keyid", "n", "public_key", "E(private_key)", "salt", "username", "password", "d",
                 "padding"])
            for private_entrance in private_key_rings[user].values():
                writer.writerow([private_entrance.timestamp, private_entrance.keyid, private_entrance.n,
                                 private_entrance.public_key, private_entrance.private_key, private_entrance.salt,
                                 user, private_entrance.password, private_entrance.d, private_entrance.padding])
    with open("data/public_keys.csv", "w", encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "keyid", "n", "public_key", "username"])
        for pair in public_key_rings.values():
            for public_entrance in pair.values():
                writer.writerow([public_entrance.timestamp, public_entrance.keyid, public_entrance.public_key.n,
                                 public_entrance.public_key.e, public_entrance.username])
    with open("data/received_mails.csv", "w", encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["username", "mails"])
        for user in users:
            writer.writerow([user, users[user]])


def read_from_files():
    with open("data/public_keys.csv", "r", encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if not row or row[0] == "timestamp":
                continue
            timestamp = float(row[0])
            keyid = int(row[1])
            n = int(row[2])
            e = int(row[3])
            username = row[4]
            public_key = rsa.PublicKey(n, e)
            if username in public_key_rings:
                public_key_rings[username][keyid] = PublicEntrance(timestamp, public_key, username)
            else:
                public_key_rings[username] = {keyid: PublicEntrance(timestamp, public_key, username)}
    with open("data/received_mails.csv", "r", encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if not row or row[0] == "username":
                continue
            users[row[0]] = int(row[1])
    for user in users:
        with open(f"users/user_{user}/private_keys.csv", "r", encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if not row or row[0] == "timestamp":
                    continue
                timestamp = float(row[0])
                n = int(row[2])
                e = int(row[3])
                en_private_key = row[4]
                salt = row[5]
                username = row[6]
                password = row[7]
                d = int(row[8])
                padding = int(row[9])
                private_entrance = PrivateEntrance(timestamp, n, e, en_private_key, username, password, salt, d,
                                                   padding)
                if username in private_key_rings:
                    private_key_rings[username][private_entrance.keyid] = private_entrance
                else:
                    private_key_rings[username] = {private_entrance.keyid: private_entrance}
    for user in users:
        if user not in private_key_rings:
            private_key_rings[user] = {}
        if user not in public_key_rings:
            public_key_rings[user] = {}


def save_personal_public_keys(username):
    with open(f"users/user_{username}/public_keys.csv", "w", encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'Key ID', 'Public Key N', 'Public Key E', 'Username'])

        for public_entrance in public_key_rings_current_user.values():
            writer.writerow([
                public_entrance.timestamp,
                public_entrance.keyid,
                public_entrance.public_key.n,
                public_entrance.public_key.e,
                public_entrance.username
            ])


def load_public_key_rings(username):
    file_path = f"users/user_{username}/public_keys.csv"

    with open(file_path, mode='r', encoding='utf-8', newline='') as file:
        reader = csv.reader(file)
        try:
            header = next(reader)  # Try to read the header row
        except StopIteration:
            # If StopIteration is raised, it means the file is empty
            print(f"No public keys found for user {username}.")
            return

        for row in reader:
            if row == []: continue
            timestamp = float(row[0])  # Convert timestamp to float if necessary
            keyid = int(row[1])  # Convert keyid to int if necessary
            n = int(row[2])  # Convert n to int if necessary
            e = int(row[3])  # Convert e to int if necessary
            username = row[4]  # Username as string

            # Assuming you have a class or structure for PublicEntrance
            public_entrance = PublicEntrance(timestamp, rsa.PublicKey(n, e), username)

            # Populate your dictionary with keyid as the key
            public_key_rings_current_user[keyid] = public_entrance


def export_key_to_pem(username, keyid):
    if username in public_key_rings and keyid in public_key_rings[username]:
        entry = public_key_rings[username][keyid]
        data = {
            'public_key': {
                'n': entry.public_key.n,
                'e': entry.public_key.e,
            },
            'timestamp': entry.timestamp,
            'username': entry.username,
            'keyid': entry.keyid,
        }
        json_data = json.dumps(data).encode('utf-8')

        file_path = f'exports/exported_public_key_{username}_{keyid}.pem'
        # Encode JSON data to base64 and prepare PEM format
        b64_data = base64.b64encode(json_data)
        pem_data = f"-----BEGIN CUSTOM DATA-----\n{b64_data.decode('utf-8')}\n-----END CUSTOM DATA-----\n"

        # Write to PEM file
        with open(file_path, 'w') as f:
            f.write(pem_data)


def import_data_from_pem(file_path):
    with open(file_path, 'r') as f:
        pem_data = f.read()

    # Extract base64-encoded data from PEM format
    start_marker = '-----BEGIN CUSTOM DATA-----'
    end_marker = '-----END CUSTOM DATA-----'
    data_start_index = pem_data.find(start_marker) + len(start_marker)
    data_end_index = pem_data.find(end_marker)
    base64_data = pem_data[data_start_index:data_end_index].strip()

    # Decode base64 and deserialize JSON
    json_data = base64.b64decode(base64_data)
    data = json.loads(json_data)

    # Extract components
    keyid = data['keyid']
    public_key_data = data['public_key']
    timestamp = data['timestamp']
    username = data['username']
    public_key = rsa.PublicKey(public_key_data['n'], public_key_data['e'])
    public_key_rings_current_user[keyid] = PublicEntrance(timestamp, public_key, username)

    save_personal_public_keys(frontend.PGPWindow.current_user)


def export_keypair_to_pem(username, keyid, password):
    if username in private_key_rings and keyid in private_key_rings[username]:
        entry = private_key_rings[username][keyid]
        data = {
            'key_pair': {
                'n': entry.n,
                'e': entry.public_key,
                'd': decrypt_private_key(entry.private_key, password, entry.padding)
            },
            'timestamp': entry.timestamp,
            'username': entry.username,
            'keyid': entry.keyid,
            'salt': entry.salt,
            'padding': entry.padding,
            'password': entry.password,
        }
        json_data = json.dumps(data).encode('utf-8')

        file_path = f'exports/exported_keypair_{username}_{keyid}.pem'
        # Encode JSON data to base64 and prepare PEM format
        b64_data = base64.b64encode(json_data)
        pem_data = f"-----BEGIN CUSTOM DATA-----\n{b64_data.decode('utf-8')}\n-----END CUSTOM DATA-----\n"

        # Write to PEM file
        with open(file_path, 'w') as f:
            f.write(pem_data)


def import_datapair_from_pem(file_path, user):
    with open(file_path, 'r') as f:
        pem_data = f.read()

    # Extract base64-encoded data from PEM format
    start_marker = '-----BEGIN CUSTOM DATA-----'
    end_marker = '-----END CUSTOM DATA-----'
    data_start_index = pem_data.find(start_marker) + len(start_marker)
    data_end_index = pem_data.find(end_marker)
    base64_data = pem_data[data_start_index:data_end_index].strip()

    # Decode base64 and deserialize JSON
    json_data = base64.b64decode(base64_data)
    data = json.loads(json_data)

    # Extract components
    keyid = data['keyid']
    key_pair = data['key_pair']
    timestamp = data['timestamp']
    # username = data['username']
    public_key = rsa.PublicKey(key_pair['n'], key_pair['e'])
    salt = data['salt']
    padding = data['padding']
    password = data['password']

    e = key_pair['e']
    n = key_pair['n']
    en_private_key, padding = encrypt_private_key(key_pair['d'], password)
    private_entrance = PrivateEntrance(timestamp, n, e, en_private_key, user, password, salt, key_pair['d'], padding)
    if user in private_key_rings:
        private_key_rings[user][private_entrance.keyid] = private_entrance
    else:
        raise ValueError("User does not exist")
    if user in public_key_rings:
        public_key_rings[user][private_entrance.keyid] = PublicEntrance(timestamp, public_key, user)
    else:
        raise ValueError("User does not exist")
    save_to_files()
