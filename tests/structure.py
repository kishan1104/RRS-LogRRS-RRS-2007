import random
from cryptography.hazmat.primitives import hashes


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



def ElEnc(pp, y, m):
	k = random.randint(1, pp['p']-2)
	c1 = pow(pp['g'],k,pp['p'])
	c2 = m * pow(y,k,pp['p'])
	return c1, c2, k

def ElDec(pp, x, c1, c2):
    m = (pow(c1, pp['p']-1-x)*c2)%pp['p']
    return m

def KeyGen(pp):
    pass

def Sign(Y,n,pi,pk_rev,msg,pp):

    c1,c2,u = ElEnc(pp,pk_rev,Y[pi])
    # print('enc=','c1',c1,'c2',c2,'u',u)
    rz = random.randint(1,pp['p']-1)
    # print(rz)
    nonces = {}
    K1:int
    #for generating nonces
    for i in range(n):
        if i == pi:
            nonces[i] = 1
            continue
        ci = random.randint(1,pp['p']-1)
        nonces[i] = ci
    # print('nonces',nonces)
    aggK1 = 1
    for i in range(n):
        if i == pi:
            continue
        top1 = pow(c2,nonces[i], pp['p'])
        top2 = pow(inv2(Y[i],pp['p']),nonces[i], pp['p'])
        top = top1*top2 % pp['p']
        # top = int(((c2**nonces[i] % pp['p']))*((inv2(Y[i],pp['p'])**nonces[i]) % pp['p']) % pp['p'])
        # print(f'c2/z{i}**c{i}={top}')
        aggK1 *=top

    K1 = (pow(pk_rev,rz, pp['p'])*(aggK1 % pp['p'])) % pp['p']
    # print('pkrev^rz=',pow(pk_rev,rz,pp['p']))
    digest = hashes.Hash(hashes.SHA256())
    strY = ''
    
    #Aggrigating all public keys to string

    for i in Y:
        strY += str(i)
    
    #data for the hash function input

    data = strY+str(msg)+str(K1)
    digest.update(data.encode()) 
    hash_value = digest.finalize()
    hashed_int = int.from_bytes(hash_value, byteorder='big')

    nonces[pi] = (hashed_int % pp['p'] - (sum(nonces.values()) % pp['p'] )) % pp['p']
    # print('nonces pi',nonces[pi])
    tildez = (rz-(nonces[pi]*u)) % (pp['p']-1)
    # print('k1',K1)
    # print('tildez',tildez)
    return(u,c1,c2,nonces,tildez,K1,rz)

def Vrfy(Y,n,pk_rev,msg,signature,pp):
    # print(signature[2])
    aggK = 1
    K:int
    K1:int
    for i in range(n):
        aggK *= pow(Y[i],signature[2][i],pp['p'])
        # print(aggK)
    
    aggK1 = 1
    for i in range(n):
        top = ((pow(signature[3][1],signature[2][i],pp['p']))*(pow(inv2(Y[i],pp['p']),signature[2][i],pp['p']))) % pp['p']
        aggK1 *=top
        # print(aggK1)
    
    K = ((pp['g']**signature[0])*(aggK))% pp['p'] 
    K1 = ((pk_rev**signature[1])*(aggK1)% pp['p'])

    strY = ''.join(str(i) for i in Y)
    data = strY+str(msg)+str(K)+str(K1)
    print("string in vrfy",data)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    hash_value = digest.finalize()
    hashed_int = int.from_bytes(hash_value, byteorder='big')
    print(hashed_int % pp['p'])
    if (hashed_int)%pp['p'] == (sum(signature[2].values()) % pp['p']):
        print("verification successful")
        return 1
    else:
        print("failed to verify")
        return 0
    print("in verify K=",K," K1=",K1)



if __name__=="__main__":
    pp ={'g':5,'p':23,}

    Y = [17,18,4,19,9]
    pi = 0
    sk_pi = 7

    sk_pairs = [7,12,4,15,20]

    # print(inv2(4,23))
    signature = Sign(Y,5,pi,17,"hello",pp)
    print(signature)
    # verify = Vrfy(Y,5,19,"hello",signature,pp)

    # array = []

    # for i in range(1,24):
    #     array.append(5**i % 23)
    
    # print(sorted(array))
    # nonces = [19,1,10,10,3]
    # rx = 14 
    # rz = 16
    # K = 4
    # K1 = 18
    # c1 = 15625
    # c2 = 458613811
    # pi = 0
    # inverse = []
    # for i in range(5):
    #     inverse.append(inv2(nonces[i],23))
    # print(inverse)
    # zici = []
    # #calculating zi^-ci for sign
    # for i in range(5):
    #     zici.append((c2**nonces[i])*(inverse[i]**nonces[i]))
    # print(zici)

    # totalprod = 1
    # #value K in sign
    # for i in range(5):
    #     if i == pi:
    #         continue
    #     totalprod*=zici[i]
    # KSign = (18**rz)*totalprod
    # KSign = KSign % 23
    # print(KSign)

    # for i in range(5):
    #     totalprod *=zici[i]
    # Kvrfy = (18**13)*totalprod
    # Kvrfy = Kvrfy % 23
    # print(Kvrfy)