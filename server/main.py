from flask import Flask, request
import json
import random
import base64
import os
import threading
import time
import asyncio, asyncvnc


from OpenSSL import crypto, SSL
from sshfs import SSHFileSystem

virt_name="RD-"

def cert_gen(
    emailAddress="emailAddress",
    commonName="commonName",
    countryName="NT",
    localityName="localityName",
    stateOrProvinceName="stateOrProvinceName",
    organizationName="organizationName",
    organizationUnitName="organizationUnitName",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "private.key",
    CERT_FILE="selfsigned.crt"):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')

    list = ["",""]
    list[0] = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    list[1] = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")
    return list

def id_generator():
    return ''.join(random.choice("0123456789ABCDEF") for _ in range(8))

def key_exchange(username,key,fs):

    fs.mkdir('./.config/sunshine/credentials/')
    fs.mkdir('./.config/autostart')
    found_this_key = False
    try:
        lines = []
        #details = fs.info('./.config/sunshine/sunshine_state.json')
        with fs.open('./.config/sunshine/sunshine_state.json') as stream:
            lines.append(stream.read().decode("utf-8") )
        str_a = ''.join(lines) 

        arr = json.loads(str_a)
        #print(arr)
    except:
        print("###########################################30")


    try:
        #print("##### 34 ##### key found &&&&&&&&&&&&&&&&")
        for i in arr["root"]["devices"][0]["certs"]:#засовываем сетефикат клиента
            if str(i).replace("\n","\\n") == key:
                found_this_key = True
                #print("##### 36 ##### key found ###################")
        #print("##### 38 ##### key found ??????????????????????")
    except:
        print(81)

    if found_this_key != True:
        print("########################46########################################")
        #arr["root"]["devices"][0]["certs"].append(key)
        #print("key added")
        arr = '''{
        "username": "sunshine",
        "salt": "kCd-OKCjjI&Bscjz",
        "password": "AABA4B75B81EBAC9B20B749B64BBEF032DCB8BE3CFFA16AC0F4809D27F568449",
        "root": {
            "uniqueid": "405F54E6-C1D4-A705-5D1D-5908749B8567",
            "devices": [
                {
                    "uniqueid": "0123456789ABCDEF",
                    "certs": [
                        "'''+key+'''"
                    ]
                }
            ]
        }
        }'''
        arr = json.loads(arr)

        fs.mkdir('.config/sunshine/')
        arr["root"]["uniqueid"] = id_generator()
    print(107)
    
    json_string = json.dumps(arr)
    #print("###########################60##################################"+json_string+"###############################################################")

    #file_name = "./virts/"+username+"/home/"+username+"/.config/sunshine/sunshine_state.json"
    with fs.open('./.config/sunshine/sunshine_state.json', 'wb') as stream:
        stream.write(json_string)
    
    print(116)
    lines = []
    cert = ""
    #details = fs.info('./.config/sunshine/sunshine_state.json')
    try:
        with fs.open('./.config/sunshine/credentials/cacert.pem') as stream:
            lines.append(stream.read().decode("utf-8") )
        for i in lines:
            cert += i
    except:
        list = cert_gen()
        cert = list[0]
        with fs.open('./.config/sunshine/credentials/cacert.pem', 'wb') as stream:
            stream.write(list[0])
        with fs.open('./.config/sunshine/credentials/cakey.pem', 'wb') as stream:
            stream.write(list[1])
        print("")
    with fs.open('./.config/autostart/sun.desktop', 'wb') as stream:
            stream.write('''[Desktop Entry]
            Type=Application
            Name=Sunshine
            Exec=/bin/sunshine''')
    
    return [arr["root"]["uniqueid"],cert,True]


async def run_client(login,passord):
    sc=os.popen("sudo virsh vncdisplay "+virt_name+""+login).read().partition(':')[2]
    sc = int(sc)+5900
    #print(sc)

    async with asyncvnc.connect('127.0.0.1',sc) as client:
        time.sleep(0.5)
        client.keyboard.write(login)
        time.sleep(0.5)
        client.keyboard.press('Tab')
        time.sleep(0.5)
        client.keyboard.write(passord)
        time.sleep(0.5)
        client.keyboard.press('Return')

def preparing_(user_name,cert_base64,password):
    
    q = os.popen("sudo virsh list --all | grep "+virt_name+"" + user_name).read()
    if(q == ""):
        #print("виртуалки нету")
        virt_running[user_name] = "clone"
        #print("clone")
        os.system("sudo virt-clone --original "+virt_name+"clear --name "+virt_name+""+user_name+" --file /var/lib/libvirt/images/"+virt_name+""+user_name+".qcow2")
        #print("sudo virt-clone --original fedora-clear --name fedora-"+user_name+" --file /var/lib/libvirt/images/fedora-"+user_name+".qcow2")
        #print("готово")

    

    q = os.popen("sudo virsh domifaddr "+virt_name+""+user_name+" | grep ipv4 | cut -c47-70 | rev  | cut -c4-19 | rev").read().replace("\n","")
    if q == "":
        os.system("sudo virsh start "+virt_name+""+user_name)
        virt_running[user_name] = "starting"
        print("starting")
        
        time.sleep(20)
    #print("sudo virsh domifaddr "+virt_name+""+user_name+" | grep ipv4 | cut -c47-70 | rev  | cut -c4-19 | rev")
    q = os.popen("sudo virsh domifaddr "+virt_name+""+user_name+" | grep ipv4 | cut -c47-70 | rev  | cut -c4-19 | rev").read().replace("\n","")
    
    virt_running[user_name] = "setup"
    
    #print("setup")
    #print("ip="+q)
    
    #######################################################################
    #######################################################################
    #######################################################################
    #######################################################################
    #######################################################################
    
    #comand = "bash -c 'mkdir -p ./virts/"+user_name+"; umount ./virts/"+user_name+"; sshfs -o StrictHostKeyChecking=no  -o allow_other,default_permissions root@"+q+":/ ./virts/"+user_name+" -o IdentityFile=/home/lefor/.ssh/id_rsa'"
    #print(comand)
    #os.system(comand)
    fs = SSHFileSystem(
        q,
        username=user_name,
        password=password
    )   
    b1 = cert_base64.encode("UTF-8")
    d = base64.b64decode(b1)
    cert = d.decode("UTF-8")
    
    w = key_exchange(user_name,cert,fs)
    print(w)

    arr = [w[0],q,w[1],True]
    #print(arr)
    data = json.dumps(arr)
    b1 = data.encode("UTF-8")
    d = base64.b64encode(b1)
    data_base64 = d.decode("UTF-8")
    
    #virt_running[user_name] = os.popen("ls ./virts/"+user_name+"/").read()
    time.sleep(5)
    
    asyncio.run(run_client(user_name,password))
    
    
    
    #os.system("ssh -o IdentityFile=/home/lefor/.ssh/id_rsa -o StrictHostKeyChecking=no root@"+q+"  su "+user_name+" -c sunshine &")
    #print("ssh -o IdentityFile=/home/lefor/.ssh/id_rsa -o StrictHostKeyChecking=no root@"+q+"  su "+user_name+" -c sunshine &")
    time.sleep(5)

    virt_running[user_name] = data_base64

    




app = Flask(__name__)

SERVER_IP = "192.168.122.1"

virt_running = {}

@app.route('/key_exchange')
def main():
    user_name = request.args.get('user_name')
    password = request.args.get('password')
    cert_base64 = request.args.get('cert')
    
    #сюда нало пррверку на логин и пароль
    virt_running[user_name]="preparing"
    #threading.start_new_thread(preparing_(user_name))
    threading.Thread(target=preparing_, args=(user_name,cert_base64,password,)).start()

    return "ok" 

@app.route('/runing')
def run():
    user_name = request.args.get('user_name')
    
    out = "error"
    for i in virt_running:
        if(i == user_name):
            out = virt_running[i]

    return out

app.run(debug = True,host="0.0.0.0")


