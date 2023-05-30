import requests
import json
import base64
import threading
import time
from plyer import notification


import sys
import os
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QLineEdit, QGridLayout, QMessageBox)


IP_ = "127.0.0.1"
lines = []
file_name = ""
def connect(login,password):
    q = os.popen("whoami").read().replace("\n","")
    file_name = "/home/"+q+"/.config/Moonlight Game Streaming Project/Moonlight.conf"
    #print(file_name)
    f = open(file_name,"r")
    lines = f.readlines()
    #old_data = f.read()
    f.close()
    #print(lines)
    for i,y in enumerate(lines):
        if y[0:11] == "certificate":
            cert = y[24:-3]
            #print(cert)
        if y == "[hosts]\n":
            #print(y)
            q = len(lines)
            #print(q)
            i += 1
            ii = i
            while i < q:
                #print(i)
                lines[i] = ""
                #del lines[i]
                i += 1

    clear_lines = []
    for i in lines:
        if i != "":
            clear_lines.append(i)

    lines = clear_lines

    #print(cert)

    with open(file_name, "w") as file:
        for line in lines:
            file.write(line)

    b = cert.encode("UTF-8")
    e = base64.b64encode(b)
    cert_base64 = e.decode("UTF-8")
    #print(cert_base64)
    response = requests.get('http://'+IP_+':5000/key_exchange?user_name='+login+'&password='+password+'&cert='+cert_base64).text
    #print("###############################3")
    #print('http://'+IP_+':5000/key_exchange?user_name='+login+'&password='+password+'&cert='+cert_base64)
    #print("###############################3")

    #response = "qwe"
    return (response == "ok")

def running_(user,ip,self):


    q=True
    while q:
        time.sleep(2)
        response = requests.get('http://'+IP_+':5000/runing?user_name='+user).text
        #print("######################################\n response\n################################# \n\n"+response+"############################\n################################")
        try:
            b = response.encode("UTF-8")
            e = base64.b64decode(b)
            response = e.decode("UTF-8")
            arr = json.loads(response)
            if arr[3] == False:
                return False
            q = os.popen("whoami").read().replace("\n","")
            file_name = "/home/"+q+"/.config/Moonlight Game Streaming Project/Moonlight.conf"
            #file_name = "/home/"+user+"/.config/Moonlight Game Streaming Project/Moonlight.conf"
            f = open(file_name,"r")
            lines = f.readlines()
            #old_data = f.read()
            f.close()
            print("##############\n"+arr[2].replace("\n","\\n")+"\n##############")
            lines.append("1\\localaddress="+arr[1])
            lines.append("\n1\\localport=47989\n")
            lines.append("1\\srvcert=@ByteArray("+arr[2].replace("\n","\\n")+")")
            lines.append("\n1\\uuid="+arr[0])
            lines.append("\nsize=1")
            
            with open(file_name, "w") as file:
                for line in lines:
                    file.write(line)
            
            q=False
            print("run Moonlight")
            os.system("bash -c './Moonlight-4.3.1-x86_64.AppImage stream "+arr[1]+" Desktop &' | grep 1243123123")
        except:
            #notification.notify(title='RemoteRD', message=response)
            self.setWindowTitle(response)
            if(response == "error"):
                sys.exit(app.exec_())
        

    return "ok"

class LoginForm(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Login Form')
        self.resize(500, 120)

        layout = QGridLayout()

        label_name = QLabel('<font size="4"> Username </font>')
        self.lineEdit_username = QLineEdit()
        self.lineEdit_username.setPlaceholderText('Please enter your username')
        layout.addWidget(label_name, 0, 0)
        layout.addWidget(self.lineEdit_username, 0, 1)

        label_password = QLabel('<font size="4"> Password </font>')
        self.lineEdit_password = QLineEdit()
        self.lineEdit_password.setPlaceholderText('Please enter your password')
        layout.addWidget(label_password, 1, 0)
        layout.addWidget(self.lineEdit_password, 1, 1)

        button_login = QPushButton('Login')
        button_login.clicked.connect(self.check_password)
        layout.addWidget(button_login, 2, 0, 1, 2)
        layout.setRowMinimumHeight(2, 75)

        self.setLayout(layout)

    def check_password(self):
        msg = QMessageBox()
        # тут делает кучу запросов на пароли и ключи
        data = connect(self.lineEdit_username.text(),self.lineEdit_password.text())
        if data:
            #if self.lineEdit_username.text() == 'user' and self.lineEdit_password.text() == '1':
            #msg.setText('Success')
            threading.Thread(target=running_, args=(self.lineEdit_username.text(),IP_,self)).start()
            #running_(self.lineEdit_username.text(),IP_,self)
            #app.quit()
        else:
            msg.setText('Incorrect Password')
            #msg.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)

    form = LoginForm()
    form.show()

    sys.exit(app.exec_())
