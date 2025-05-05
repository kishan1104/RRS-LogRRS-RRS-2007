from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Random.random import randint


curve = 'P-256'
key = ECC.generate(curve= curve)
g = key.public_key().pointQ
n = ECC._curves[curve].order
p = ECC._curves[curve].p
n = int(n)
p = int(p)
sk = key.d
pk = sk * g

def schnorr_sign(M,sk):
    r = randint(1,n-1)
    R = r*g
    hashe = SHA256.new((str(M)+str(R.x)).encode()).digest()
    e = int.from_bytes(hashe,byteorder='big') % n

    s = r+int(sk)*e % n

    return (e,s)

def getInv(xP):
    inv_P = ECC.EccPoint((xP.x),-int(xP.y)%p,curve=curve)
    return inv_P

def schnorr_vrfy(M,sig,pk):
    e,s = sig
    R = s*g + getInv(e*pk)
    msg_hash = SHA256.new((str(M)+str(R.x)).encode()).digest()
    ev = int.from_bytes(msg_hash,byteorder='big') % n

    return ev == e

message = "Hello Schnorr!"
signature = schnorr_sign(message, sk)

print("\nSignature:", signature)

print("vrfy = ",schnorr_vrfy(message,signature,pk))

# # Generate ECC key pair (secp256r1)
# curve = 'P-256'
# key = ECC.generate(curve=curve)
# G = key.public_key().pointQ  # Generator point
# q = ECC._curves[curve].order  # Order of the group
# p = ECC._curves[curve].p
# print( "this is q",q)
# private_key = key.d  # Secret key (scalar)
# public_key = private_key * G  # Public key (EC point)

# # print("Private Key:", private_key)
# # print("Public Key:", (public_key.x, public_key.y))

# # ---- SIGNATURE GENERATION ----
# def schnorr_sign(message, private_key):
#     """ Generate a Schnorr signature """
#     print(q)
#     k = randint(1, int(q)-1)  # Random nonce
#     R = k * G  # Commitment (EC point)
    
#     # Hash message and commitment
#     msg_hash = SHA256.new((str(R.x) + str(message)).encode()).digest()
#     e = int.from_bytes(msg_hash, byteorder='big') % int(q)  # Challenge

#     s = (k + e * int(private_key)) % int(q)  # Signature component

#     return (R.x, s)

# # ---- SIGNATURE VERIFICATION ----
# def schnorr_verify(message, signature, public_key):
#     """ Verify a Schnorr signature """
#     R_x, s = signature
#     msg_hash = SHA256.new((str(R_x) + str(message)).encode()).digest()
#     e = int.from_bytes(msg_hash, byteorder='big') % int(q)  # Recompute e

#     eP = e * public_key  # Multiplication is supported

#     # Manually negate the point (-eP) using modular arithmetic
#     eP_neg = ECC.EccPoint(int(eP.x), (-int(eP.y)) % int(p), curve=curve)  # Negate Y-coordinate

#     # Compute R' = s*G + (-eP)
#     R_prime = s * G + eP_neg  # This is the corrected operation

#     return R_prime.x == R_x

# # Test the Schnorr Signature
# message = "Hello Schnorr!"
# signature = schnorr_sign(message, private_key)

# print("\nSignature:", signature)

# # Verify the Signature
# is_valid = schnorr_verify(message, signature, public_key)
# print("\nSignature Valid:", is_valid)



