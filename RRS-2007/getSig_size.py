import time
import pickle
import sys
from charm.core.engine.util import objectToBytes
group = PairingGroup('SS1024')
g = Setup()

def Generate_n_keys(n):
    publickeys = []
    privateKeys = []

    for i in range(n):
        sk,pk = KeyGen(g)
        publickeys.append(pk)
        privateKeys.append(sk)
    return publickeys,privateKeys
def get_signature_size(signature, num_elements=3):
    partial = signature[:num_elements]
    serialized = b''.join([objectToBytes(elem, group) for elem in partial])
    return len(serialized)   # size in bytes
  # size in bytes


def Ring_Sig_Time():
    sizes = [4,8,16,32,64,128,256,512]
    for i in sizes:
        pkList,skList = Generate_n_keys(i)
        pi = 0
        RA = []
        rv = i-1
        for j in range(i):
          RA.append(pkList[j])



        start_time = time.time()
        sigma = Sign(g,pkList,skList[pi],RA,'hello',pi)
        sign_time = (time.time() - start_time) *1000 # Average per operation
        # print(f"Time for signature Gen of {i}: {sign_time:.9f} milli seconds")

        start_time = time.time()
        Verify(g,pkList,RA,'hello',sigma)
        vrfy_time = (time.time() - start_time) *1000 # Average per operation
        # print(f"Time for signature vrfy of {i}: {vrfy_time:.9f} milli seconds")

        size = get_signature_size(sigma,len(sigma))

        size_kb = size / 1024
        print(f"Size: {size_kb:.2f} KB")

        # start_time = time.time()
        # rrs.vrfy(signature,"Hello")
        # vrfy_time = (time.time() - start_time) *1000 # Average per operation
        # print(f"Time for signature vrfy of {i}: {vrfy_time:.9f} milli seconds")

        # ElEnc(publickeys[4],publickeys[rev],G)

        start_time = time.time()
        Revoke(g,pkList,RA,skList[rv],'hello',sigma,rv)
        vrfy_time = (time.time() - start_time) *1000 # Average per operation
        # print(f"Time for signature revoke of {i}: {vrfy_time:.9f} milli seconds")

