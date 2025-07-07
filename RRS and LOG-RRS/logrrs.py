#!/usr/bin/env python
# coding: utf-8

#The basic Sign and Verify in the Code Refers to the RRS Scheme.



import secrets
import time
from sympy import mod_inverse
from math import log2
from fastecdsa import keys, curve, ecdsa
from hashlib import sha256, sha512, sha384
import pickle




# define basic parameter
my_curve = curve.P256
g = my_curve.G
p = my_curve.q
generator_u = g * secrets.randbelow(p)
generator_u2 = g * secrets.randbelow(p)

# define basic operation
# int(c, 16) is to convert hexadecmical strings to actual numbers, I don't think it would limit the size of the number
def A(r):
    return g * r
def Z(sk,r,c):
    c = int(c, 16)
    return (r - c*sk) % p
def Z1(sk,r,c):
    return (r - c*sk) % p
def V1(z):
    return g * z
def V2(pk, c):
    c = int(c, 16)
    return pk*c
def V_z(z, pk, c):
    c = int(c, 16)
    return (g*z) + (pk*c)

# setup function, not actually called since parameter are already defined
def Setup(parameter):
    return parameter, hash


# key generation calling ecc keyGen
def KeyGen():
#     sk is before pk
    return keys.gen_keypair(my_curve)



# converting a ecc point to string form: taking its x and y coodinates
def pt_to_string(point):
    a = str(point.x)
    b = str(point.y)
    return a + b


# helper method to convert a list of numbers to a string
def list_to_string(l):
    a = ''
    for i in range (len(l)):
        a = a + str(l[i])
############################################# set a = hash(a) before returning it #######
    return a

# helper method to check if (i -1)'s jth bit is a 1
def check_bit(i, j):
    temp = i
    if ((temp >> j) & 1) == 1:
        return 1
    return -1

#El Gamal Encryption 
def ElEnc(M,pk,g,n):
    k = secrets.randbelow(n-1)+1
    c1 = k*g
    c2 = M + (k*pk)
    return c1,c2,k

#El Gamal Decryption
def ElDec(sk,c1, c2):
    s = c1*sk
    m = c2 - (s)

    return m

# RRS Sign algorithm based on DualRing
# signature size is O(n)
def basic_sign(m, pk_list,pk_r, sk, j):
    # print(type(pk_r))
    c1,c2,u = ElEnc(pk_list[j],pk_r,g,p)
    r = secrets.randbelow(p)
    rz = secrets.randbelow(p)
    c_array = [None] * len(pk_list)
    universal_pk_string = list_to_string(pk_list)
    R = g * r
    R2 = pk_r * rz
    summation_except_j = 0
    for i in range (len(pk_list)):
        if i == j:
            continue
        temp_c = secrets.randbelow(p)
        c_array[i] = temp_c
        R = R + (pk_list[i]* temp_c)
        R2 = R2 + ((c2-pk_list[i])* temp_c)
        summation_except_j = (summation_except_j + temp_c)
    my_string = m + universal_pk_string + pt_to_string(R) +pt_to_string(R2)
    C = sha256(my_string.encode()).hexdigest()
    C_number = int(C, 16) % p
#     with mod p won't work
    c_array[j] = (C_number - summation_except_j) % p
    xt = Z1(sk,r,c_array[j])
    zt = Z1(u,rz,c_array[j])



    h_list = [None] * len(pk_list)
    for i in range (len(pk_list)):
        h_list[i] = c2-pk_list[i]
    return c_array, xt,zt, C_number, R, (c1,c2),R2,h_list

# RRS Verify based on DualRing
def basic_verify(m, pk_list,pk_r, sigma):
    c_array = sigma[0]
    universal_pk_string = list_to_string(pk_list)
    xt = sigma[1]
    zt = sigma[2]
    R = g * xt
    R2 = pk_r * zt
    for i in range (len(pk_list)):
        R = R + (pk_list[i]* c_array[i])
        R2 = R2 + ((sigma[5][1]-pk_list[i])* c_array[i])
    my_string = m + universal_pk_string + pt_to_string(R) + pt_to_string(R2)
    result = (int(sha256(my_string.encode()).hexdigest(), 16)) % p
    if (sum(c_array)) % p != result:
        print("basic verify failed")
        return 0
    return 1

def revoke(sigma,sk):
  return ElDec(sk,sigma[5][0],sigma[5][1])




# pk_list: public key list
# u1,u2: another generator
# b: at first a list of 1s
# a: list of all c in algorithm 4
# Loop in NISA Proof
def P_proof(pk_list,h_list, this_u, this_u2, b, a, L, R):
#     start_time = time.time()
    n = len(a)
#     additional check
#     if len(a) != len(b) or len(a) != len(pk_list):
#         print("len check failed")
    if n == 1:
        return (L, R, a, b)

    n_prime = int(n / 2)
#     c_L and c_R should be two scalars
    c_L = 0
    c_R = 0
    for i in range (n_prime):
        c_R += ((a[n_prime + i] * b[i]) % p)
        c_L += ((a[i] * b[n_prime + i]) % p)

#     my_L and my_R should be two pts on ECC
    my_L = this_u * c_L
    my_R = this_u * c_R
    my_L2 = this_u2 * c_L
    my_R2 = this_u2 * c_R
#     print('stage 1 time: ', time.time() - start_time)
#     start_time = time.time()

    for ii in range (n_prime):
        my_L = my_L + (pk_list[n_prime + ii] * a[ii])
        my_R = my_R + (pk_list[ii] * a[n_prime + ii])
        my_L2 = my_L2 + (h_list[n_prime + ii] * a[ii])
        my_R2 = my_R2 + (h_list[ii] * a[n_prime + ii])
    L.append([my_L,my_L2])
    R.append([my_R,my_R2])
    my_string = pt_to_string(my_L) + pt_to_string(my_R) + pt_to_string(my_L2) + pt_to_string(my_R2)


#     x should be a number
    x = int(sha256(my_string.encode()).hexdigest(), 16)
#     pk_prime_list is g' in the algorithm
    pk_prime_list = [None] * n_prime
    h_prime_list = [None] * n_prime

    a_prime_list = [None] * n_prime

    x_inverse = mod_inverse(x, p)
#   b[i] for every i in range should be the same value
    b_value = (x_inverse * b[0] + x * b[n_prime]) % p
    b_prime_list = [b_value] * n_prime
    for iii in range (n_prime):
        pk_prime_list[iii] = pk_list[iii] * x_inverse + pk_list[n_prime + iii] * x
        h_prime_list[iii] = h_list[iii] * x_inverse + h_list[n_prime + iii] * x
        a_prime_list[iii] = (x * a[iii] + x_inverse * a[n_prime + iii]) % p

#     recursion
    return P_proof(pk_prime_list,h_prime_list, this_u, this_u2, b_prime_list, a_prime_list, L, R)









# b: at first a list of 1s
# c is the summation of ci in DualRing
# pi: the returned product from P
# Loop in NISA Verify
def V(pk_list,h_list, this_u,this_u2, P, P2, pi):
    L = pi[0]
    R = pi[1]
    a = pi[2][0]
    b = pi[3][0]

    original_length = len(pk_list)
    log_length = int(log2(original_length))
    x_list = [None] * log_length
#     x_list is a list of hashed numbers
    for i in range (log_length):
        my_string = pt_to_string(L[i][0]) + pt_to_string(R[i][0]) + pt_to_string(L[i][1]) + pt_to_string(R[i][1])
        x_list[i] = int(sha256(my_string.encode()).hexdigest(), 16)
    y_list = [None] * original_length
#     y is a list of numbers
    for ii in range (original_length):
        product = 1
        for iii in range (log_length):
            if check_bit(ii, iii) == 1:
                product = (product * x_list[log_length - iii - 1]) % p
            else:
                inverse = mod_inverse(x_list[log_length - iii - 1], p)
                product = (product * inverse) % p
        y_list[ii] = product
    g_prime = pk_list[0] * y_list[0]
    h_prime = h_list[0] * y_list[0]
    for iv in range (1, original_length):
        g_prime = g_prime + (pk_list[iv] * y_list[iv])
        h_prime = h_prime + (h_list[iv] * y_list[iv])
    left_check = P
    left_check2 = P2
    for v in range (log_length):
        x_sq = (x_list[v] ** 2) % p
        left_check = left_check + (L[v][0] * x_sq)
        left_check2 = left_check2 + (L[v][1] * x_sq)
        left_check = left_check + (R[v][0] * mod_inverse(x_sq, p))
        left_check2 = left_check2 + (R[v][1] * mod_inverse(x_sq, p))
    right_check = (g_prime + this_u * b)*a
    right_check2 = (h_prime + this_u2 * b)*a
    if left_check == right_check and left_check2 == right_check2:
        return 1
    return 0


# P: a point on ECC
# a: a list of all Cs
def NISA_Proof(pk_list,h_list, P,P2, c, a):
    my_string = pt_to_string(P) + pt_to_string(generator_u) + str(c)
    h = int(sha256(my_string.encode()).hexdigest(), 16)
    uprime = generator_u * h
    my_string2 = pt_to_string(P2) + pt_to_string(generator_u2) + str(c)
    h2 = int(sha256(my_string2.encode()).hexdigest(), 16)
    uprime2 = generator_u2 * h2
    b = [1] * len(a)
    return P_proof(pk_list,h_list, uprime, uprime2, b, a, [], [])


def NISA_Verify(pk_list,h_list, P,P2, c, pi):
    my_string = pt_to_string(P) + pt_to_string(generator_u) + str(c)
    h = int(sha256(my_string.encode()).hexdigest(), 16)
    uprime = generator_u * h
    P_prime = P + uprime * c
    my_string2 = pt_to_string(P2) + pt_to_string(generator_u2) + str(c)
    h2 = int(sha256(my_string2.encode()).hexdigest(), 16)
    uprime2 = generator_u2 * h2
    P_prime2 = P2 + uprime2 * c
    return V(pk_list,h_list, uprime,uprime2, P_prime, P_prime2, pi)


def full_Sign(m, pk_list, sk, j,rj):
    start_time = time.time()
    sigma = basic_sign(m, pk_list,pk_list[rj] ,sk, j) #c_array, xt,zt, C_number, R, (c1,c2),R2,h_list
    c_array = sigma[0]
    xt = sigma[1]
    zt = sigma[2]
    c = sigma[3]
    R = sigma[4]
    R2 = sigma[6]
    P = R - (g * xt)
    P2 = R2 - (pk_list[rj] * zt)
    h_list = sigma[7]
    pi = NISA_Proof(pk_list,h_list, P, P2, c, c_array)
    return c,xt, zt, R, R2, pi, P,P2,h_list


def full_Verify(m, pk_list, sigma):
    start_time = time.time() #c,xt, zt, R, R2, pi, P,P2
    c = sigma[0]
    xt = sigma[1]
    zt = sigma[2]
    R = sigma[3]
    R2 = sigma[4]
    pi = sigma[5]
    h_list = sigma[8]
    P = R - (g * xt)
    P2 = R2 - (pklist[2] * zt)
    if NISA_Verify(pk_list,h_list, P,P2, c, pi) == 0:
        print("NISA CHECK FAILED")
        return 0
    my_string = m + list_to_string(pk_list) + pt_to_string(R) + pt_to_string(R2)
    check = int(sha256(my_string.encode()).hexdigest(), 16)
    if c == check:
        return 1
    print("other check failed")
    return 0

# testing
pklist = []
sklist = []
for i in range(8):
  foo,pk = KeyGen()
  pklist.append(pk)
ssk, ppk = KeyGen()
random_pos = secrets.randbelow(8)
my_sk,pklist[random_pos] = ssk,ppk

# def getpublickeysize(pk):
#     serialized = pickle.dumps(pk)
#     return len(serialized)
# print(getpublickeysize(pklist[0]))
# print(getpublickeysize(ssk))
hh = full_Sign("hello", pklist, my_sk ,random_pos,2)
print(full_Verify("hello", pklist, hh))

