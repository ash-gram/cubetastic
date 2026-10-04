"""Server-only OAuth provisioning. Plaintext credentials never enter Git."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

DIRECTORY = Path('/etc/cubetastic')
KEY = DIRECTORY / 'oauth-setup-private.pem'

def openssl(*args, data=None):
    return subprocess.run(['openssl', *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=True).stdout

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['key', 'apply', 'destroy-key'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run this provisioning command as root on the server.')
    os.umask(0o077)
    DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    if args.action == 'key':
        if not KEY.exists():
            openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-out', str(KEY))
        print(openssl('pkey', '-in', str(KEY), '-pubout').decode(), end='')
    elif args.action == 'apply':
        sealed = json.loads((Path(__file__).parent / 'google-client.sealed.json').read_text())
        fingerprint = hashlib.sha256(openssl('pkey', '-in', str(KEY), '-pubout', '-outform', 'DER')).hexdigest()
        if sealed['recipient_sha256'] != fingerprint:
            raise SystemExit('Encrypted setup belongs to a different server key.')
        decrypted = openssl('pkeyutl', '-decrypt', '-inkey', str(KEY),
                            '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
                            '-pkeyopt', 'rsa_mgf1_md:sha256', data=base64.b64decode(sealed['ciphertext'], validate=True))
        credentials = json.loads(decrypted)
        client_id, secret = credentials['client_id'], credentials['client_secret']
        if not re.fullmatch(r'[A-Za-z0-9._-]+\.apps\.googleusercontent\.com', client_id) or not re.fullmatch(r'[A-Za-z0-9_\-]{10,256}', secret):
            raise SystemExit('Invalid Google client configuration.')
        destination = DIRECTORY / 'google.env'
        temporary = DIRECTORY / 'google.env.new'
        temporary.write_text(f'GOOGLE_CLIENT_ID={client_id}\nGOOGLE_CLIENT_SECRET={secret}\n')
        temporary.chmod(0o600)
        temporary.replace(destination)
        print('Google OAuth configured in the server-only protected environment file.')
    else:
        if not (DIRECTORY / 'google.env').is_file():
            raise SystemExit('Configure OAuth before retiring the setup key.')
        KEY.unlink(missing_ok=True)
        print('One-time decryption key removed. Historical setup ciphertext is no longer decryptable with this server key.')

if __name__ == '__main__':
    main()
