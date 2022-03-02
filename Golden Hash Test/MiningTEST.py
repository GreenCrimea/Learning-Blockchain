import datetime
import hashlib

timestamp = str(datetime.datetime.now())

nonce = 1

print("beginning mining for golden hash")
while True:
    data = f"{timestamp}{nonce}"
    hashOutput = hashlib.sha256(data.encode()).hexdigest()

    if hashOutput[:8] == "63756E74": #63 75 6E 74 = cunt (ASCII)
        print("Found golden hash")
        print(hashOutput)
        print(f"it took {nonce} hashes to find it")
        break
    else:
        print(f"{nonce}:{hashOutput}")
        nonce += 1
