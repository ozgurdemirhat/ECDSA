import hashlib
import pickle
import sys
import ecdsa
from sage.all_cmdline import *
import gmpy2

order = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449

def modular_inv(a, b):
    return int(gmpy2.invert(a, b))

def load_csv(filename, limit=None):
    msgs = []
    sigs = []
    fp = open(filename)
    n = 0
    if limit is None:
        limit = -1
    for line in fp:
        if (limit == -1) or (n < limit):
            l = line.rstrip().split(",")
            R, S, Z = l
            msgs.append(int(Z, 16))
            sigs.append((int(R, 16), int(S, 16)))
            n += 1
    return msgs, sigs

def make_matrix(msgs, sigs, B):
    m = len(msgs)
    sys.stderr.write("Using: %d sigs...\n" % m)
    matrix = Matrix(QQ, m + 2, m + 2)
    msgn, rn, sn = [msgs[-1], sigs[-1][0], sigs[-1][1]]
    rnsn_inv = rn * modular_inv(sn, order)
    mnsn_inv = int(hashlib.sha512(str(msgn).encode()).hexdigest(),16) * modular_inv(sn, order)
    for i in range(0, m):
        matrix[i, i] = order
    for i in range(0, m):
        x0 = ((sigs[i][0] * modular_inv(sigs[i][1], order)) - rnsn_inv)
        x1 = (int(hashlib.sha512(str(msgs[i]).encode()).hexdigest(),16) * modular_inv(sigs[i][1], order)) - mnsn_inv
        matrix[m + 0, i] = x0
        matrix[m + 1, i] = x1
    matrix[m + 0, i + 1] = (2**(521-B)) / order
    matrix[m + 0, i + 2] = 0
    matrix[m + 1, i + 1] = 0
    matrix[m + 1, i + 2] = 2**(521-B)
    return matrix

def privkeys_from_reduced_matrix(msgs, sigs, matrix):
    keys = []
    msgn, rn, sn = [int(hashlib.sha512(str(msgs[-1]).encode()).hexdigest(),16), sigs[-1][0], sigs[-1][1]]
    for row in matrix:
        potential_nonce_diff = row[0]
        potential_priv_key = (
            (sn * int(hashlib.sha512(str(msgs[0]).encode()).hexdigest(),16))
            - (sigs[0][1] * msgn)
            - (sigs[0][1] * sn * potential_nonce_diff)
        )
        potential_priv_key *= modular_inv(
            (rn * sigs[0][1]) - (sigs[0][0] * sn), order
        )
        key = potential_priv_key % order
        if key not in keys:
            keys.append(key)
    return keys

def display_keys(keys):
    gen = ecdsa.NIST521p.generator
    with open('pub_key.pkl', 'rb') as f:
        pub_key = pickle.load(f)
        pub_cor=(pub_key.point.x(), pub_key.point.y())
    for key in keys:
        is_pub=ecdsa.ecdsa.Public_key(gen, gen * int("%064x\n" % key,16))
        is_pub_cor=(is_pub.point.x(), is_pub.point.y())
        if(pub_cor==is_pub_cor):
            print("%064x\n" % key,end="")

filename = "messages.csv"
B = 9 #Number of the bits that are same
limit = int(input("How many signatures do you want to use?: "))
msgs, sigs = load_csv(filename, limit=limit)
matrix = make_matrix(msgs, sigs , B)
new_matrix = matrix.LLL()
keys = privkeys_from_reduced_matrix(msgs, sigs , new_matrix)
display_keys(keys)