# import random
# from cryptography.hazmat.primitives import hashes


# def inv2(n, q):
#     """another PN invmod: from euler totient function
#     - n ** (q - 1) % q = 1 => n ** (q - 2) % q = n ** -1 % q
#     """
#     assert q > 2
#     s, p2, p = 1, n, q - 2
#     while p > 0:
#         if p & 1 == 1:
#             s = s * p2 % q
#         p, p2 = p >> 1, pow(p2, 2, q)
#         pass
#     return s



# def ElGamalEnc(pk,msg,pp):
    
#     k = random.randint(1,pp['p']-1)
#     msg_int = msg
#     if type(msg) != int:

#         msg_bytes = msg.encode('utf-8')
#         msg_int = int.from_bytes(msg_bytes,'big')
    
    

#     print(msg_int)
#     c1 = (pp['g']**k) % pp['p']
#     c2 = (msg_int*(pk**k)) % pp['p']
#     C = (c1,c2)
#     print(C)
#     return C,k

# def ElGamalDec(sk,cypher,pp):

#     c1 = cypher[0]
#     c2 = cypher[1]
#     s = (c1**sk) % pp['p']
#     c1inv = inv2(s,pp['p'])
#     c1sk = c2**c1inv % pp['p']
#     return (c1sk) 

# def KeyGen(pp):
#     pass

# def Sign(Y,n,pi,pk_pi,sk_pi,pk_rev,msg,pp):
#     C,u = ElGamalEnc(pk_pi,pk_rev,pp)

#     rx = random.randint(1,pp['p']-1)
#     rz = random.randint(1,pp['p']-1)

#     nonces = {}
#     K:int
#     K1:int
#     #for generating nonces
#     for i in range(n):
#         if i == pi:
#             nonces[i] = 0
#             continue
#         ci = random.randint(1,pp['p']-1)
#         nonces[i] = ci
    
#     #Calculating K value
#     aggK = 1
#     for i in range(n):
#         if i == pi:
#             continue
#         aggK *= (Y[i]**nonces[i])

#     K = ((pp['g']**rx)*(aggK)) % pp['p']


#     #Calculating K prime value
#     aggK1 = 1
#     for i in range(n):
#         if i == pi:
#             continue
#         top = int((C[1]**nonces[i])*(inv2(Y[i],pp['p'])**nonces[i]))
#         aggK1 *=top

#     K1 = ((pk_rev**rz)*(aggK1)) % pp['p']


#     digest = hashes.Hash(hashes.SHA256())
#     strY = ''
    
#     #Aggrigating all public keys to string

#     for i in Y:
#         strY += str(i)
    
#     #data for the hash function input

#     data = strY+str(msg)+str(K)+str(K1)
#     digest.update(data.encode()) 
#     hash_value = digest.finalize()
#     hashed_int = int.from_bytes(hash_value, byteorder='big')
#     #check here for modulus operatrion
#     print("in sign ",hashed_int % pp['p'])
    
#     #Calculating c[pi] value
    
#     nonces[pi] = (hashed_int % pp['p'] - (sum(nonces.values()) % pp['p'] )) % pp['p']
    
#     #Calculating tildex and tildey values

#     tildex = (rx - nonces[pi]*sk_pi) % (pp['p'] - 1)

#     tildez = (rz-nonces[pi]*u) % (pp['p']-1)

#     signature = (tildex,tildez,nonces,C,u,rx,rz)
#     print("in sign K =",K," K1 =",K1)
    
#     return signature

# def Vrfy(Y,n,pk_rev,msg,signature,pp):
#     # print(signature[2])
#     aggK = 1
#     K:int
#     K1:int
#     for i in range(n):
#         aggK *= (Y[i]**signature[2][i])
#         # print(aggK)
    
#     aggK1 = 1
#     for i in range(n):
#         top = int((signature[3][1]**signature[2][i])*(inv2(Y[i],pp['p'])**signature[2][i]))
#         aggK1 *=top
#         # print(aggK1)
    
#     K = ((pp['g']**signature[0])*(aggK))% pp['p'] 
#     K1 = ((pk_rev**signature[1])*(aggK1)% pp['p'])

#     strY = ''.join(str(i) for i in Y)
#     data = strY+str(msg)+str(K)+str(K1)

#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(data.encode())
#     hash_value = digest.finalize()
#     hashed_int = int.from_bytes(hash_value, byteorder='big')
#     print(hashed_int % pp['p'])
#     print("in verify K=",K," K1=",K1)
#     if (hashed_int)%pp['p'] == (sum(signature[2].values()) % pp['p']):
#         print("verification successful")
#         return 1
#     else:
#         print("failed to verify")
#         return 0
    

# def GiveK1(Y,n,pi,pk_rev,pp,rz,nonces,C,tildez):
#     K1:int

#     #Calculating K prime value
#     aggK1 = 1
#     for i in range(n):
#         if i == pi:
#             continue
#         aggK1 *= (C[1]**nonces[i])*(inv2(Y[i],pp['p'])**nonces[i])
        
#     inverse = []
#     for i in range(5):
#         inverse.append(inv2(nonces[i],23))
#     print(inverse)
#     zici = []
#     #calculating zi^-ci for sign
#     # for i in range(5):
#     #     zici.append((c2**nonces[i])*(inverse[i]**nonces[i]))
#     print(zici)

#     totalprod = 1
#     #value K in sign
#     for i in range(5):
#         if i == pi:
#             continue
#         totalprod*=zici[i]
#     KSign = (18**rz)*totalprod
#     KSign = KSign % 23
#     # print(KSign)
    
#     # K1 = ((pk_rev**rz)*(aggK1)) % pp['p']


#     # digest = hashes.Hash(hashes.SHA256())
#     # strY = ''
    
#     #Aggrigating all public keys to string

#     # for i in Y:
#     #     strY += str(i)
    
#     #data for the hash function input

#     # data = strY+str(msg)+str(K)+str(K1)
#     # digest.update(data.encode()) 
#     # hash_value = digest.finalize()
#     # hashed_int = int.from_bytes(hash_value, byteorder='big')
#     #check here for modulus operatrion
#     # print("in sign ",hashed_int % pp['p'])
    
#     #Calculating c[pi] value
    
#     # nonces[pi] = (hashed_int % pp['p'] - (sum(nonces.values()) % pp['p'] )) % pp['p']
    
#     #Calculating tildex and tildey values

#     # tildex = (rx - nonces[pi]*sk_pi) % (pp['p'] - 1)

#     # tildez = (rz-nonces[pi]*u) % (pp['p']-1)

#     # signature = (tildex,tildez,nonces,C)
#     print("in sign K1 =",KSign)

#     aggK1 = 1
#     for i in range(n):
#         # if i == pi:
#         #     continue
#         top = int((C[1]**nonces[i])*(inv2(Y[i],pp['p'])**nonces[i]))
#         aggK1 *=top
    
    
#     K1 = ((pk_rev**tildez)*(aggK1)% pp['p'])
#     print("in vrfy test",K1)
    
    


# if __name__=="__main__":
#     pp ={'g':5,'p':23,}

#     # Y = [17,18,4,19,9]
#     # pi = 0
#     # sk_pi = 7

#     # sk_pairs = [7,12,4,15,20]

#     # # print(inv2(4,23))
#     # # signature = Sign(Y,5,pi,17,sk_pi,19,"hello",pp)
#     # nonces = [7,13,1,1,17]
#     # rx = 5 
#     # rz = 21
#     # K = 12
#     # K1 = 7
#     # c1 = 3814697265625
#     # c2 = 267198604589286774829171
#     # tildez = 5
#     # pi = 0
#     # GiveK1(Y,5,pi,19,pp,rz,nonces,(c1,c2),tildez)
#     C,k = ElGamalEnc(17,12,pp)
#     print("dec",ElGamalDec(7,C,pp))
#     # print(signature)
#     # verify = Vrfy(Y,5,19,"hello",signature,pp)
    