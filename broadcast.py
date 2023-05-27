import os
import datetime

class Broadcast:
    
    def sendmail(self, message):
        if not message:
            return
        command = f"echo '" + message + "'"
        print(command)
        os.system(command)# Mail alert (Mail reducted; used to use the mail command with a local smtp server)
        os.system('mv /var/log/IDS/alert.log /var/log/IDS/alert.log.{0}.{1}.{2}'.format(datetime.datetime.now().day, datetime.datetime.now().hour, datetime.datetime.now().minute))
