import random
from cryptography.hazmat.primitives import hashes


pp={'g':5,'p':23}
pk = 19
sk =15


def inv2(n, q):
    """another PN invmod: from euler totient function
    - n ** (q - 1) % q = 1 => n ** (q - 2) % q = n ** -1 % q
    """
    assert q > 2
    s, p2, p = 1, n, q - 2
    while p > 0:
        if p & 1 == 1:
            s = s * p2 % q
        p, p2 = p >> 1, pow(p2, 2, q)
        pass
    return s

def Sign(pp,sk,m,r):
    r = random.randint(1,pp['p']-1)
    R = pow(pp['g'],r,pp['p'])
    digest = hashes.Hash(hashes.SHA256())
    data = str(m)+str(R)
    print("data in sign",data)
    digest.update(data.encode()) 
    hash_value = digest.finalize()
    hashed_int = int.from_bytes(hash_value, byteorder='big')

    y = (r - sk*hashed_int) % (pp['p']-1)

    return (hashed_int,y)


def Vrfy(pp,pk,m,e,y):
    # x = ((pow(pp['g'],y))*(pow(pow(pk,-1,pp['p']),e,pp['p']))) % pp['p']
    x = pow(pp['g'],y,pp['p'])*pow(pk,e,pp['p']) % pp['p']
    digest = hashes.Hash(hashes.SHA256())
    data = str(m)+str(x)
    print("data in vrfy",data)
    digest.update(data.encode()) 
    hash_value = digest.finalize()
    hashed_int = int.from_bytes(hash_value, byteorder='big')
    if(e == hashed_int):
        print("verified")
    else:
        print("failure")

e,y = Sign(pp,4,1234,3)

Vrfy(pp,4,1234,e,y)

# print(pow(17,-1,23))

