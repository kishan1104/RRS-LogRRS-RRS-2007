class MyClass:
    def __init__(self):
        self._data = []  # ✅ Initialize here

    @property
    def data(self):
        return self._data  # ✅ No error now

obj = MyClass()
print(obj.data)  # Output: [1, 2, 3]




















# from Crypto.PublicKey import ECC
# from Crypto.Hash import SHA256
# from Crypto.Random.random import randint
# from Elgaml import ElEnc,ElDec,getInv

# curve = 'P-256'
# o = int(ECC._curves[curve].order)
# p = int(ECC._curves[curve].p)
# G = ECC._curves[curve].G


# def generate_publickey():
#     key = ECC.generate(curve=curve)
#     sk = key.d
#     pk = sk*G
#     return (pk,sk)

# def RRS_sign(e,n,pi,Y,sk_pi,pk_rev,M):
#     c1,c2,u = ElEnc(Y[pi],pk_rev,G,o)
#     rx = randint(1,o-1)
#     rz = randint(1,o-1)
#     nonces = {}
#     K = rx*G
#     for i in range(n):
#         if i==pi:
#             nonces[i] = 1
#             continue
#         ci = randint(1,o-1)
#         nonces[i] = ci
#     aggK = None
#     for i in range(n):
#         if i == pi:
#             continue
#         if aggK == None:
#             aggK = nonces[i]*Y[i]
#         else:
#             aggK += nonces[i]*Y[i]
#     K += aggK

#     aggK1 = None
#     K1 = rz*pk_rev

#     for i in range(n):
#         if i == pi:
#             continue
#         if aggK1 == None:
#             aggK1 = (c2+getInv(Y[i]))*nonces[i]
#         else:
#             aggK1 += (c2+getInv(Y[i]))*nonces[i]
#     K1 += aggK1

#     strY = ''
    
#     #Aggrigating all public keys to string

#     for i in Y:
#         strY += str(i)

#     data = str(e)+strY+str(M)+str(K.x)+str(K1.x)
#     print(data)
#     msg_hash = SHA256.new(data.encode()).digest()
#     hash_value = int.from_bytes(msg_hash,byteorder='big')

#     nonces[pi] = (hash_value - sum(nonces.values())) % o
#     # print(sum(nonces.values()))

#     tildex = (rx - nonces[pi]*int(sk_pi)) % o
#     tildez = (rz - nonces[pi]*u) % o

#     signature = (tildex,tildez,nonces,(c1,c2))

#     return signature

# def RRS_vrfy(e,n,Y,pk_rev,M,signature):
#     aggK = None
#     K = signature[0]*G
#     K1 = signature[1]*pk_rev
#     tx,tz,nonces,C = signature

#     print()
#     # print(sum(nonces.values()))
#     aggK1 = None

#     for i in range(n):
#         if aggK == None:
#             aggK = nonces[i]*Y[i]
#         else:
#             aggK += nonces[i]*Y[i]
#     K+= aggK

#     for i in range(n):
#         if aggK1 == None:
#             aggK1 = (C[1] + getInv(Y[i]))*nonces[i]
#         else:
#             aggK1 += (C[1] + getInv(Y[i]))*nonces[i]
#     K1 += aggK1

#     strY = ''.join(str(i) for i in Y)
#     data = str(e) +strY + str(M) +str(K.x)+ str(K1.x)
#     print("data in vrfy",data)
#     msg_hash = SHA256.new(data.encode()).digest()
#     hash_value = int.from_bytes(msg_hash,byteorder='big')
    
#     print(hash_value-1%o ,"\n",sum(nonces.values())%o)


# if __name__=='__main__':
#     publickeys = []
#     privateKeys = []
#     for i in range(5):
#         pk,sk = generate_publickey()
#         publickeys.append(pk)
#         privateKeys.append(sk)
#     n = len(publickeys)
#     pi = 2
#     rev = 4
#     signature = RRS_sign('e',n,pi,publickeys,privateKeys[pi],publickeys[rev],"Hello")

#     RRS_vrfy('e',n,publickeys,publickeys[rev],"Hello",signature)

#     # print(signature)