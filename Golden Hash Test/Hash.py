import datetime
import hashlib

timestamp = str(datetime.datetime.now())
# print(timestamp)
#
# timestamp_bytes = timestamp.encode()
# print(timestamp_bytes)
#
# hash_bytes = hashlib.sha256(timestamp_bytes)
# print(hash_bytes)
#
# hash = hash_bytes.hexdigest()
# print(hash)

hash = hashlib.sha256(timestamp.encode()).hexdigest()
print(hash)

print(hash[:4])
if hash[:4] == "0000":
    print("Found golden hash")
else:
    print("hash is not the one")
