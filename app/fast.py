# from Crypto.PublicKey import RSA

# key = RSA.generate(2048)
# password = "haslo123"

# encrypted = key.export_key(passphrase=password)

# with open("encrypted.bin","wb") as f:
#     f.write(encrypted)

# encoded = open("encrypted.bin","rb").read()

# res = RSA.import_key(encoded,passphrase=password)

# print(res.export_key())
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

public = key.public_key().export_key().decode("utf-8")

print(type(public))