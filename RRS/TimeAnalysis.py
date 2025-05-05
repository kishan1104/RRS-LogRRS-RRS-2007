import time
from Crypto.PublicKey import ECC
from Crypto.Random.random import randint
from Elgaml import getInv,ElEnc,ElDec
from Crypto.Hash import SHA256
import RRS_Vanet
import sys

curve = 'P-256'
G = ECC._curves[curve].G
scalar = 123456789
def TimeAnalysis():
    

    # Number of iterations for better measurement
    iterations = 1000  

    # Measure the time for multiple multiplication operations
    start_time = time.time()
    for _ in range(iterations):
        result_mult = scalar * G  # Elliptic curve point multiplication
    mult_time = (time.time() - start_time) / iterations *1e6 # Average per operation
    print(f"Average Multiplication Time: {mult_time:.9f} micro seconds")

    # Generate two elliptic curve points for addition
    P = 3 * G  
    Q = 7 * G  

    # Measure the time for multiple addition operations
    start_time = time.time()
    for _ in range(iterations):
        result_add = P + Q  # Elliptic curve point addition
    add_time = (time.time() - start_time) / iterations *1e6 # Average per operation
    print(f"Average Addition Time: {add_time:.9f} micro seconds")


    start_time = time.time()
    for _ in range(iterations):
        rx = randint(1,int(ECC._curves[curve].order)-1)
    random_time = (time.time() - start_time) / iterations *1e6 # Average per operation
    print(f"Average Random Number Generation Time: {random_time:.9f} micro seconds")

    start_time = time.time()
    for _ in range(iterations):
        inv = getInv(P)
    inv_time = (time.time() - start_time) / iterations *1e6 # Average per operation
    print(f"Average Time for inverse of ecc point: {inv_time:.9f} micro seconds")

    start_time = time.time()
    for _ in range(iterations):
        msg_hash = SHA256.new(str(P).encode()).digest()
    hash_time = (time.time() - start_time) / iterations *1e6 # Average per operation
    print(f"Average Time for Hash Operation: {hash_time:.9f} micro seconds")


def Generate_n_keys(n):
    publickeys = []
    privateKeys = []
    for i in range(n):
        pk,sk = RRS_Vanet.generate_publickey()
        publickeys.append(pk)
        privateKeys.append(sk)
    return publickeys,privateKeys


def Ring_Sig_Time():
    sizes = [2,4,8,16,32,64,128,256,512]
    for i in sizes:
        publickeys,privatekeys = Generate_n_keys(i)
        n = i
        pi = 0
        rev = i-1
        rrs = RRS_Vanet.RRS('event',n,publickeys,publickeys[rev])

        

        start_time = time.time()
        signature = rrs.sign(privatekeys[pi],pi,'Hello')
        sign_time = (time.time() - start_time) *1000 # Average per operation
        print(f"Time for signature Gen of {i}: {sign_time:.9f} milli seconds")

        start_time = time.time()
        rrs.vrfy(signature,"Hello")
        vrfy_time = (time.time() - start_time) *1000 # Average per operation
        print(f"Time for signature vrfy of {i}: {vrfy_time:.9f} milli seconds")

        
        
        # start_time = time.time()
        # rrs.vrfy(signature,"Hello")
        # vrfy_time = (time.time() - start_time) *1000 # Average per operation
        # print(f"Time for signature vrfy of {i}: {vrfy_time:.9f} milli seconds")

        # ElEnc(publickeys[4],publickeys[rev],G)

        start_time = time.time()
        (rrs.revoke(signature,privatekeys[rev],"Hello"))
        vrfy_time = (time.time() - start_time) *1000 # Average per operation
        print(f"Time for signature revoke of {i}: {vrfy_time:.9f} milli seconds")


Ring_Sig_Time()   

def SizeCalculation():
    # Generate ECC key pair
    curve = 'P-256'
    key = ECC.generate(curve=curve)
    sk = key.d  # Secret Key
    pk = key.public_key().export_key(format="DER")  # Public Key

    # Generate a sample signature
    G = ECC._curves[curve].G
    scalar = randint(1, int(ECC._curves[curve].order))
    i = 2
    publickeys,privatekeys = Generate_n_keys(i)
    n = i
    pi = 0
    rev = i-1
    rrs = RRS_Vanet.RRS('event',n,publickeys,publickeys[rev])

    

    
    signature = rrs.sign(privatekeys[pi],pi,'Hello')
    
    # Compute sizes
    private_key_size = sys.getsizeof(sk)
    public_key_size = sys.getsizeof(pk)  # Export as DER format
    signature_size = sys.getsizeof(signature[0])
    signature_size1 = sys.getsizeof(signature[1])
    signature_size2 = sys.getsizeof(signature[2][0])
    signature_size3 = sys.getsizeof(signature[2][1])
    signature_size4 = sys.getsizeof(signature[3][0])
    signature_size5 = sys.getsizeof(signature[3][1])

    # # Print results
    print(f"Private Key Size: {private_key_size} KiloBytes")
    print(f"Public Key Size: {public_key_size/1024} KiloBytes")
    print(f"x tilda Size: {signature_size/1024} KiloBytes")
    print(f"z tilda Size: {signature_size1/1024} KiloBytes")
    print(f"nonces 1 Size: {signature_size2/1024} KiloBytes")
    print(f"nonces 2 Size: {signature_size3/1024} KiloBytes")
    print(f"C1 Size: {signature_size4/1024} KiloBytes")
    print(f"C2 Size: {signature_size5/1024} KiloBytes")

# SizeCalculation()

def ActualSigSize(n):
    size =  (60*(n+2))+(56*2)
    print(f"Signature Size for {n} users is: {size/1000} KiloBytes")
    return size




# Generate an ECC key pair (P-256 curve)
key = ECC.generate(curve='P-256')

# Private key size: Fixed size for the curve (e.g., 256 bits for P-256)
private_key_size = ECC._curves[curve].order.size_in_bits()

# Public key size: Based on the coordinates (X, Y)
public_key_size = 2 * key.pointQ.size_in_bits()  # Since a public key has (X, Y)

# Print results
print(f"Private Key Size: {private_key_size//8} bytes")
print(f"Public Key Size: {public_key_size//8} bytes")


    # print("size in KB",size)
