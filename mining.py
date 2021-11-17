from hashlib import sha256

def hash2(a, b):
    contcat = (a[::-1])+(b[::-1])
                
    h = sha256(sha256(contcat).digest()).digest()
    return h[::-1]

# nacteni tx do listu
with open("txids.txt", "r", encoding="utf-8") as f:
    txids = [w.strip() for w in f.readlines()]

# list tx do pomocného listu jako bytes
pomlist = []
for i in range(len(txids)):
    pomlist.append(bytes.fromhex(txids[i]))

# spočteme merkle root
while len(pomlist) > 1:
    newlist = []
    for i in range(0, len(pomlist), 2):
        newlist.append(hash2(pomlist[i], (pomlist[i+1] if (i+1) < len(pomlist) else pomlist[i])))
    pomlist = newlist

# hlavička
ver =  bytes.fromhex("20400000")
prev_block = bytes.fromhex("000000000000000000036c5d254177454359ecec1d2f84e1c138c1565954966a")
merkle_root = pomlist[0]
ts = bytes.fromhex("6194f0d7") # Wed Nov 17 2021 12:08:55 GMT+0000
bits = bytes.fromhex("170c69ea")

# jaký je target?
exp = bits[0]
coef = int.from_bytes(bits[1:], 'big')
target = coef * 256 ** (exp-3)

print("           target je: {}".format(hex(target)[2:].zfill(64)))

nonce = 0x29a13700 # startovní nonce; hardcore si sem dají nulu.

# těžíme!
while nonce < 0xffffffff:
    tx = ver[::-1] + prev_block[::-1] + merkle_root[::-1] + ts[::-1] + bits[::-1] + nonce.to_bytes(4, 'big')
    hash = sha256( sha256(tx).digest() ).digest()
    res = int.from_bytes(hash, "little") < target
    print("pro nonci {}: {} ; {}".format(hex(nonce), (hash[::-1]).hex(), "OK!" if res else "nic"))
    if res:
        break
    else:
        nonce += 1

print("          target byl: {}".format(hex(target)[2:].zfill(64)))

