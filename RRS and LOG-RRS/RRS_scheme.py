
import secrets
from logrrs import KeyGen,basic_sign,basic_verify,revoke

#using the basic sign function from logrrs
if __name__=="__main__":
    pklist = []
    sklist = []
    for i in range(8):
        foo,pk = KeyGen()
        pklist.append(pk)
    ssk, ppk = KeyGen()
    random_pos = secrets.randbelow(8)
    my_sk,pklist[random_pos] = ssk,ppk
    sign = basic_sign("hello", pklist,pklist[2], my_sk ,random_pos)
    print(basic_verify("hello", pklist, pklist[2], sign))

