from pyDes import triple_des 

def keyGenerator():
    key='a 16 or 24 byte password' #chng it to random one and save and organise them securely
    return key

def encrypt_privileges(data,key):
    ciphertext = triple_des(key).encrypt(str(data), padmode=2)
    return ciphertext

def decrypt_privileges(data,key):
    plain_text = triple_des(key).decrypt(data, padmode=2)
    the_dict = eval(plain_text)
    return the_dict