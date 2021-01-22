import datetime
import os
import sys

import pkcs11

label = sys.argv[1]
user_pin = "1234"

lib = pkcs11.lib(os.environ.get("PKCS11_MODULE", "/usr/lib/libsofthsm2.so"))
token = lib.get_token(token_label=label)
session = token.open(user_pin=user_pin, rw=True)
now = datetime.datetime.utcnow().isoformat()
key_label = f"{label} @ {now[:19]}"
print(key_label)
public, private = session.generate_keypair(pkcs11.KeyType.RSA, 2048, store=True, label=key_label)
