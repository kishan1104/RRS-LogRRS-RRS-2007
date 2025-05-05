from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Random.random import randint

curve = 'P-256'
nv = ECC._curves[curve].order
p = ECC._curves[curve].p

def getInv(xP):
    inv_P = ECC.EccPoint((xP.x),-int(xP.y)%int(p),curve=curve)
    return inv_P


def ElEnc(M,pk,g,n = int(nv)):
    k = randint(1,n-1)
    c1 = k*g
    # print(type(k),type(pk))

    c2 = M + (k*pk)
    return c1,c2,k
    

def ElDec(sk,c1, c2):
    s = c1*sk
    m = c2 + getInv(s)

    return m 

