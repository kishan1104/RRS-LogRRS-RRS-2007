from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Random.random import randint
from Elgaml import ElEnc,ElDec,getInv


def generate_publickey():
        curve = 'P-256'
        key = ECC.generate(curve=curve)
        sk = key.d
        pk = sk*(ECC._curves['P-256'].G)
        return (pk,sk)

class RRS():
    def __init__(self,e,n,Y,pk_rev):
        self.curve = 'P-256'
        self.o = int(ECC._curves[self.curve].order)
        self.p = int(ECC._curves[self.curve].p)
        self.G = ECC._curves[self.curve].G
        self.e = e
        self.n = n
        self.Y = Y
        self.pk_rev = pk_rev



    def sign(self,sk_pi,pi,M):
        c1,c2,u = ElEnc(self.Y[pi],self.pk_rev,self.G,self.o)
        rx = randint(1,self.o-1)
        rz = randint(1,self.o-1)
        nonces = {}
        K = rx*self.G
        for i in range(self.n):
            if i==pi:
                nonces[i] = 1
                continue
            ci = randint(1,self.o-1)
            nonces[i] = ci
        aggK = None
        for i in range(self.n):
            if i == pi:
                continue
            if aggK == None:
                aggK = nonces[i]*self.Y[i]
            else:
                aggK += nonces[i]*self.Y[i]
        K += aggK

        aggK1 = None
        K1 = rz*self.pk_rev

        for i in range(self.n):
            if i == pi:
                continue
            if aggK1 == None:
                aggK1 = (c2+getInv(self.Y[i]))*nonces[i]
            else:
                aggK1 += (c2+getInv(self.Y[i]))*nonces[i]
        K1 += aggK1

        strY = ''
        
        #Aggrigating all public keys to string

        for i in self.Y:
            strY += str(i)

        data = str(self.e)+strY+str(M)+str(K.x)+str(K1.x)
        # print(data)
        msg_hash = SHA256.new(data.encode()).digest()
        hash_value = int.from_bytes(msg_hash,byteorder='big')

        nonces[pi] = (hash_value - sum(nonces.values())) % self.o

        tildex = (rx - nonces[pi]*int(sk_pi)) % self.o
        tildez = (rz - nonces[pi]*u) % self.o

        signature = (tildex,tildez,nonces,(c1,c2))

        return signature

    def vrfy(self,signature,M):
        aggK = None
        
        tx,tz,nonces,C = signature
        K = tx*self.G
        K1 = tz*self.pk_rev
        aggK1 = None

        for i in range(self.n):
            if aggK == None:
                aggK = nonces[i]*self.Y[i]
            else:
                aggK += nonces[i]*self.Y[i]
        K+= aggK

        for i in range(self.n):
            if aggK1 == None:
                aggK1 = (C[1] + getInv(self.Y[i]))*nonces[i]
            else:
                aggK1 += (C[1] + getInv(self.Y[i]))*nonces[i]
        K1 += aggK1

        strY = ''.join(str(i) for i in self.Y)
        data = str(self.e) +strY + str(M) + str(K.x) + str(K1.x)
        # print("data in vrfy",data)
        msg_hash = SHA256.new(data.encode()).digest()
        hash_value = int.from_bytes(msg_hash,byteorder='big')
        
        return (hash_value-1%self.o == sum(nonces.values())%self.o)


    def revoke(self,signature,sk_rev,M):
        try:
            return ElDec(sk_rev,signature[-1][0],signature[-1][1])
        except Exception:
            print("error occored")
if __name__=='__main__':
    publickeys = []
    privateKeys = []
    for i in range(1000):
        pk,sk = generate_publickey()
        publickeys.append(pk)
        privateKeys.append(sk)
    n = len(publickeys)
    pi = 2
    rev = 4

    rrs = RRS('event',n,publickeys,publickeys[rev])

    signature = rrs.sign(privateKeys[pi],pi,'Hello')

    print( rrs.vrfy(signature,"Hello"))

    # print(RRS_revoke(signature,privateKeys[rev]) == publickeys[pi])
