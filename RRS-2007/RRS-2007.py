from charm.toolbox.pairinggroup import PairingGroup, G1, GT, ZR
from charm.toolbox.secretutil import SecretUtil
# Initialize pairing group with Type A (symmetric)

from charm.toolbox.pairinggroup import pair
from charm.toolbox.hash_module import Hash

from hashlib import sha256

# print(group.random(G1))
group = PairingGroup('SS1024')
def Setup():
  return group.random(G1)

def KeyGen(g):
  sk = group.random(ZR)
  pk = g**sk
  return sk,pk

def listToStr(l):
  s = ''
  for i in l:
    s += str(i)
  return s

def Sign(g, Y, sk, RA, msg, pi):
    r = group.random(ZR)
    r2 = group.random(ZR)
    R = r * g

    # Compute E_j = e(R, RA_j)^sk
    EJ = [pair(R, RA[i]) ** sk for i in range(len(RA))]

    # print("this is EJ", EJ)
    # Compute newE_j = e(R, RA_j)^r
    newE = [pair(R, RA[i]) ** r for i in range(len(RA))]
    # print("this is newE", newE)
    # Placeholder lists for challenges and responses
    ci = []
    si = []
    for i in range(len(Y)):
        if i != pi:
            ci.append(group.random(ZR))
            si.append(group.random(ZR))
        else:
            ci.append(group.init(ZR, 0))  # dummy
            si.append(group.init(ZR, 0))  # dummy

    # S values
    S = []
    for i in range(len(Y)):
        if i != pi:
            S.append(si[i] * g + ci[i] * Y[i])
        else:
            S.append(r2 * g)

    # Fiat-Shamir hash challenge
    T = listToStr(Y)
    RAstr = listToStr(RA)
    E = listToStr(EJ)
    EE = listToStr(newE)
    Sstr = listToStr(S)
    c_full = group.hash(T + RAstr+ str(R) + E + EE + Sstr + msg, ZR)

    # Compute the missing challenge so that sum(ci) = c_full
    ci[pi] = (c_full - sum(ci))

    # Compute final responses
    s = (r - c_full * sk)
    si[pi] = (r2 - ci[pi] * sk)
    # print("sum of Ci",sum(ci))
    return s, si, ci, EJ, R

def Verify(g,Y,RA,msg,sigma):
  s = sigma[0]
  si = sigma[1]
  ci = sigma[2]
  EJ = sigma[3]
  R = sigma[4]
  S = listToStr(Y)
  E = listToStr(EJ)
  T = listToStr(RA)
  # print("tis EJ", EJ)
  newE = [(pair(R,RA[i])**s)*(EJ[i]**sum(ci)) for i in range(len(RA))]
  # print("sum of ci",sum(ci))
  # print("this is newE",newE)
  EE = listToStr(newE)
  newSl = [si[i]*g + ci[i]*Y[i] for i in range(len(Y))]
  Sstr = listToStr(newSl)
  c = int(group.hash(S+T+str(R)+E+EE+Sstr+msg,ZR))
  # print("type of c",type(c),"type of ci",type(sum(ci)))
  return c==int(sum(ci))

def Revoke(g,Y,RA,sk_r,msg,sigma,rv):
  EJ = sigma[3]
  for i in range(len(Y)):
    if EJ[rv] == pair(Y[i],sigma[4])**sk_r:
      return Y[i]


if __name__=='__main__':
  g = Setup()
  skList = []
  pkList = []
  for i in range(5):
    sk,pk = KeyGen(g)
    skList.append(sk)
    pkList.append(pk)
  pi = 1
  RA = []
  for l in range(3):
    RA.append(pkList[l])

  sigma = Sign(g,pkList,skList[pi],RA,'hello',pi)
# print(sigma[3])
# print(sigma[0])
# print(Verify(g,pkList,RA,'hello',sigma))

# print("signer is",pkList[pi])

# print(Revoke(g,pkList,RA,skList[2],'hello',sigma,2))

