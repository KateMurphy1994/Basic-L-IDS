import os
import datetime

class Broadcast:
    
    def sendmail(self, message):
        if not message:
            return
        command = f"echo '" + message + "' | mail -s 'INTRUSION ALERT!' -a 'FROM: IDS@security.htb' kate.murphy@htb.com"
        os.system(command)# Mail alert 
        os.system('mv /var/log/IDS/alert.log /var/log/IDS/alert.log.{0}.{1}.{2}'.format(datetime.datetime.now().day, datetime.datetime.now().hour, datetime.datetime.now().minute))
