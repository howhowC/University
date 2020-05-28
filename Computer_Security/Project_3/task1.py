import os
def XorEncrypt(plain, key):
	length = len(plain)
	for i in range(length):
		plain = plain[:i] + chr(ord(plain[i])^key) + plain[i+1:]
	cipher = plain
	return cipher

#fp = open("crack_me.log", "r")
fp = open("/home/victim/Public/.Simple_Worm/crack_me.log","r")
plain = ""
cipher = fp.read()
fp.close()
key = None
for x in range(1,256):
	plain = XorEncrypt(cipher, x)
	if "Verification" in plain:
		key = x
		print("The XOR key is :" + str(key))
		break
vf = plain.split(":")
vf[1] = "0616037"
plain = vf[0] + ": " + vf[1]
#print(plain)
fp = open('/home/victim/Public/.Simple_Worm/task1_result.log','w')
fp.write(XorEncrypt(plain,key))
fp.close()
os.remove('/home/victim/Public/.Simple_Worm/crack_me.log')

