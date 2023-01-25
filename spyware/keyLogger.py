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
from scapy.layers.dns import DNSQR, DNS # For Sniffer
from scapy.layers.inet import UDP   # For Sniffer
from scapy.layers.inet6 import IPv6 # For Sniffer
from scapy.all import * # For Sniffer
import credenciais as cr  # For API
import threading    # For paralelism
import socket   # For Scanner
from IPy import IP  # For Scanner
from pyChatGPT import ChatGPT

SESSION_TOKEN = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..DhAnMOlqZKlLC4ug.p4iLKtftZq-lA5sqParHU6dIKU2ZxCiGQxIT3Wj5Wed7t-R6hQe8iUUCeW4mLPkcKE20JwnwhPgD8niXQgy69dRbHd4ovegp0M5bFt2_vgK7ayHm5K2vxCL9AzyRm4S0_qglD0lzaBDTC1_4M3fYYdZCt3s8kIUF_JgGhrzUs3fp62_bzWKjXJjp85vRnFKM2jaXX9vdPepmSaYtRBzStBtL2KK7-LIJ_8dX4xfK_ba2-lFEtw9ZDuNrF15S8sbIYGqjRpPExt925kO0dQa4kLEFjuSgJfN0v5DzQve_QlW3JvO1Ch0ZHd5_nzColzWR7bzAHxhKNdYXlyMlSttQ50se-UkEGPrK42-ZF7MxLT59g_CuyxQePouw2LQs9Db5qWoQXGvq0ala7NnbjkRakXjqYcDqFR2cpIZehY6coDV12Bb_W8t400Cp0DvYnWaQwr7vS7qkySJphp2GRNioD8m-WHVPjnWAccs4tp1UumIqC98pkakNkmvtPzGudy5jaWBS0OiQoWXIbw25IletL7VUDnsP-hczVn4ewW0-m4myroRhpRQPKY2ptLFxJ0iJ_qgraA5u9nuWiFNth0LKSVbYXpVEeGCX6SOpIPVpyxqlW_oI73WZe7n7LcDVaxF_8JopOZUwkPHrj1UcyaV3SrEzD9puJmXm-5g_vLSEFJwUf_EoP07VguDTgvkyql-Fned1_yEcMyYJOXw7LBy7bYDuQauEZ_n5c5XyZuTIm4siVha--8HPkD7imciuGUl5G7int0sMzeNPVdVk_lFvNsIXpmEgiJG2R5-3fr22WBqXMrIO5r5AvQ7oZte39naomrhIqc1I0qTLs2R4pPwpgoq1g86lzTW9KkAYLPz3CE5NfYEyD5xk0_C2siHaHkjDaF2lZTdZNGs14uevIpYLZ3UVVoMoTMoSr-0axj5VRel5BUjxAcRuqaXub3JpPtPuSXzWn6lQLB0EzoTeD2K3eIYKEEssfLFXd86jS6xTaQb5cLgpCkUTlw4MIT6e7cdIx6-Iyypz3perX9Dm1mhQ_qWMHNa8gNw0HbXtdkxJPz8RcP_F11LeE9Za7EH-5SwJPoUPNjCKCsqnvBa4fHwtWxs9QE-3a9oeDy70-p5VEv-Q3f3UvOyn4dcthu_04noV1K00g2N1ySaI7N6t8sbMRB3g8f0U5_egqs3kUkyiSG74VKMRkha46HG0oBY3ebVfOiOtRNnsVdw3dXBi12z9Liwoi-N09Iwaw1IcruUHdusqA97oQbAm8X8L9NUm7-nqNEd4XKwE1HmJZuZ88R0Swqm7edismirUczmVS4McXZXhQb0a5tiXLMkn9XR2GuRX9_YNrpdptWp3gA-P0D_zO-g8mBY-6M25w5MV1Lw3rRoYGYlH_yCpw-DLBSIN6EXStosTGHz8bNoEccWwwa9tdMenaxF1QLfXEeOz5zxyMkvuROE0hVJDMU5aIGniv2tVpRBVEeCgKORqf2lBn4AloIuGOhE-koSsyznQC6qVAbY_1n-NZg-q0F91tDFOPF7pyoIBKSIl3hDf_EGM0MTLvC8NR8Ya5nBRAYyY7HeHEZJM6TtMIBWQkAn8_aocc86c6Tg_FlhiNeJNiPkGoN2OGqikqipwZEK1dfyP9J9iSyM-3IzlrOEdsayJ0YQ41ZWM8z0kE-FHWHLI6nWVI885IvH4PYjHHlENG5FIBmMTHuICexn_5j5lqSfBDgsZ7z49S9XghMKag9Rn3N4qzsb-9LTeqZMtZYvC-C0Vkux5Rwr5C5cSSvICUmM4DOxbD9N1cGYZgLEQtOjKIf8H4brfbTEsJmJdjpjzUUxkiJOBGkN2kOC4757aSP4bokufXpbcfQHOY2HtW_UiyGh9UlmrViFlCC-IRomVPx7y3RKX7hquEoZHZrJMxj-d7iXdMePVBbcpdgghqgSyYdZA_eNxvrAMBIoPH9Vsfq28gZnCwCV9BLUD41oEWJe5lL1_bvC1ccS5QD9GWd9z4h8a8eMwYGD0v0sKUeGdRVx6hfljcaEc3iduJqHLW35BwUkdYhGXWKywendRGql2wEFF69oCieTEpRg_dTu3j0O58FyilbENbJfWyB9oDyREwBr3uRPpy6-KE6_evhfP1_layesfrRFUx58mmN6dNz_j7mYzMkmy5M9G98b9U1noEhmSA4LAKaP0uqJ_DkCNr0lfZc4arRUHu0YFfcWRy7fToAMiM8GBq-DbgBYGJGToVRhrZRnQSa28zauPKUxBXnW0N99UUO8u2IOpaM9cAboF1i_n8Q7tdpoX_exZ.2Y2EwPKQLmj_3TCsj35b7g'
SEND_REPORT_EVERY = 30
PATH_OF_THE_LOGS = "C:\keyLogger\logs\logs_" + str(time.monotonic_ns()) + ".txt"


def logging(text):
    print(text)
    arquivo = open(PATH_OF_THE_LOGS, 'a')
    arquivo.writelines(str(time.ctime()) + "    " + text + "\n")
    arquivo.close()


def is_hate_speech(self):
    dataLogs = json.dumps({"valor": 0, "frase": self.log})
    header = {'Content-type': 'application/json'}
    hateSpeech = requests.post("http://127.0.0.1:5000/predict", data=dataLogs, headers=header)

    hateSpeechJson = json.loads(hateSpeech.content)
    if hateSpeechJson[0]['valor'] == 1:
        logging("Geração de alerta por discurso de ódio: " + self.log)
        logging(str(hateSpeechJson))
        return True

    return False


def verifyng_hate_speech_chatGPT(text):
    try:
        api = ChatGPT(SESSION_TOKEN)
        str = 'Identifique se essa frase tem discurso de ódio: "' + text + '", responda com sim ou não.'
        resp = api.send_message(str)
        print(resp['message'])
        api.reset_conversation()
        if resp['message'].lower().find("sim.") == 0:
            logging("Geração de alerta por discurso de ódio no ChatGPT: " + text)
            return True
        else:
            return False
    except:
        logging("ChatGPT esta off!")


def is_bad_language(self):
    log_tokenized = self.log.split()
    with open(r'C:\keyLogger\badLanguage.txt', encoding="utf8") as file:
        contents = file.read().split(';')
        for word in log_tokenized:
            if (word.lower() in contents) or (word.upper() in contents) or (word in contents):
                logging("Palavra que gerou o alerta:" + word.lower() + "\n")
                return True


def are_malicious_process(self):
    with open('C:\keyLogger\maliciousProcess.txt', encoding="utf8") as file:
        contents = file.read().split(';')
        for proc in ps.process_iter():
            if proc.name().lower() in contents:
                if proc.name().lower() in proc.name().lower():
                    if len(proc.name()) < 2:
                        continue
                    try:
                        proc.kill()
                    except Exception:
                        logging("Error to Kill the process" + proc.name())
                        return False

                logging("Alerta gerado por causa do processo:" + proc.name() + "\n")
                self.log = "Alerta gerado por causa do processo: " + proc.name()
                return True


def get_process():
    infoSet = set()
    for proc in ps.process_iter():
        info = proc.as_dict(attrs=['pid', 'name'])
        infoSet.add(info['name'])
    process = ''
    for t in infoSet:
        process = process + t + ','

    return process


def get_image():
    buffer = io.BytesIO()
    image = ImageGrab.grab()
    image.save(buffer, format='png')
    image.close()
    b64_str = base64.b64encode(buffer.getvalue())

    return str(b64_str)


def do_login():
    dataUser = json.dumps({"login": cr.login, "password": cr.password})
    token = requests.post("http://localhost:8091/login", dataUser).text
    logging("Login realizado, token:" + token + "\n")
    return {
        'Authorization': 'Bearer ' + token,
        'Content-type': 'application/json'
    }


def send_alert(log):
    headers = do_login()

    try:
        dataImage = json.dumps({"id": 0, "productImg": log, "base64Img": get_image()}, sort_keys=True, indent=4)
        image = requests.post("http://localhost:8091/image/save", dataImage,
                              headers=headers)
        imageJson = json.loads(image.content)

        dataAlert = json.dumps({"pcId": str(gma()), "imagem": {"id": imageJson['id']}, "processos": get_process()},
                               sort_keys=True, indent=4)
        alert = requests.post("http://localhost:8091/alert/save", dataAlert, headers=headers)

        print(alert)
        logging("Alert Saved!\n" + str(alert) + "\n")
        print("Alert Saved")
        time.sleep(10)
    except Exception as error:
        logging("Error to send Alert\n" + str(error.__class__))
        print("Error to send Alert")
        pass


class Sniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.log = ''

    def sniffer(self, pkt):
        query = pkt[DNS].qd.qname.decode("utf-8") if pkt[DNS].qd != None else "?"
        with open('C:\keyLogger\sites.txt') as file:
            contents = file.read().split(';')
            for row in contents:
                query = query.rstrip('.')
                if query in row:
                    log = "Alerta gerado pelo seguinte DNS: " + query
                    logging(log)
                    send_alert(log)

    def run(self):
        logging("Iniciou do sniffer!")
        sniff(filter='udp port 53', store=0, prn=self.sniffer)


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
        if self.log and (is_hate_speech(self) or is_bad_language(self) or are_malicious_process(self) or verifyng_hate_speech_chatGPT(self.log)):
            logging("Foi enviado o report!")
            send_alert(self.log)

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
        logging("Iniciou o Scanner!")
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
                    send_alert(self.log)
    logging("Terminou o Scanner")

def update_aux_data():
    headers = do_login()
    logging("Iniciou a atualização dos dados auxiliars!")
    try:
        badLanguages = requests.get("http://localhost:8091/badLanguage/getAll", headers=headers).json()
        with open(r"C:\keyLogger\badLanguage.txt", "w") as file:
            for badLanguage in badLanguages:
                file.write(badLanguage.get('word') + ";")

        ports = requests.get("http://localhost:8091/port/getAll", headers=headers).json()
        with open(r"C:\keyLogger\vulnarable_banners.txt", "w") as file:
            for port in ports:
                file.write(port.get('vulnarableBanners') + ";")

        processes = requests.get("http://localhost:8091/process/getAll", headers=headers).json()
        with open(r"C:\keyLogger\maliciousProcess.txt", "w") as file:
            for process in processes:
                file.write(process.get('nameExe') + ";")

        websites = requests.get("http://localhost:8091/website/getAll", headers=headers).json()
        with open(r"C:\keyLogger\sites.txt", "w") as file:
            for website in websites:
                file.write(website.get('url') + ";")
    except Exception as ex:
        logging("Error to update the auxiliar data." + str(ex))



if __name__ == "__main__":
    logging("Iniciou do programa!")
    update_aux_data()
    Scanner().start()
    Sniffer().start()
    logging("Iniciou do KeyLogger!")
    keylogger = Keylogger(interval=SEND_REPORT_EVERY)
    keylogger.start()

