import csv
import pickle
import ecdsa
import random
import hashlib

secret = int(input("Write your secret in hexadecimal: "), 16)

gen = ecdsa.NIST521p.generator
order = gen.order()

pub_key = ecdsa.ecdsa.Public_key(gen, gen * secret)
priv_key = ecdsa.ecdsa.Private_key(pub_key, secret)

with open('pub_key.pkl', 'wb') as f:
    pickle.dump(pub_key, f)

n = int(input("How many messages do you want to generate?: "))

nonces = []
msgs = [random.randrange(1, order) for _ in range(n)]
for i in range(0,n):
    nonces.append(int(hashlib.sha512(str(msgs[i]+priv_key.secret_multiplier).encode()).hexdigest(),16))
sigs=[]
for i in range(0,n):
    sigs.append(priv_key.sign(int(hashlib.sha512(str(msgs[i]).encode()).hexdigest(),16), nonces[i]))


def inttohex(i):
    tmpstr = hex(i)
    return tmpstr.replace("0x", "").replace("L", "").zfill(64)

with open("messages.csv", 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    for i in range(0, len(msgs)):
        csv_writer.writerow([inttohex(sigs[i].r),inttohex(sigs[i].s), inttohex(msgs[i])])
