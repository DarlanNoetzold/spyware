import keyboard  # For Keylogger
from getmac import get_mac_address as gma  # For Mac Address
from PIL import ImageGrab  # For ScreenLogger
import base64  # For ScreenLogger
import requests  # For API
import json  # For API
import psutil as ps  # For process
from scapy.layers.dns import DNS # For Sniffer
from scapy.all import * # For Sniffer
import credenciais as cr  # For API
import threading    # For paralelism
import socket   # For Scanner
from IPy import IP  # For Scanner
import openai

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
        openai.api_key = "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"
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt='Identifique se essa frase tem discurso de ódio: "' + text + '". Responda com sim ou não',
            temperature=0.6,
        )
        if response.choices[0].text.lower().find("sim") == 0:
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
    has_error = False
    try:
        dataImage = json.dumps({"id": 0, "productImg": log, "base64Img": get_image()}, sort_keys=True, indent=4)
        image = requests.post("http://localhost:8091/image/save", dataImage,
                              headers=headers)
        imageJson = json.loads(image.content)
    except Exception as error:
        logging("Error to send Image\n" + str(error))
        print("Error to send Image")
        has_error = True

    try:
        if has_error:
            data_alert = json.dumps({"pcId": str(gma()), "processos": get_process()},
                                   sort_keys=True, indent=4)
        else:
            data_alert = json.dumps({"pcId": str(gma()), "imagem": {"id": imageJson['id']}, "processos": get_process()},
                               sort_keys=True, indent=4)
        alert = requests.post("http://localhost:8091/alert/save", data_alert, headers=headers)

        print(alert)
        logging("Alert Saved!\n" + str(alert) + "\n")
        print("Alert Saved")
        time.sleep(10)
    except Exception as error:
        logging("Error to send Alert\n" + str(error))
        print("Error to send Alert")
        pass


class Sniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.blocked_sites = set(self.read_blocked_sites())
        self.logs = []
        self.queries = set()

    def read_blocked_sites(self):
        with open('C:\keyLogger\sites.txt') as file:
            return [line.strip() for line in file]

    def sniffer(self, pkt):
        if DNS in pkt and pkt.haslayer(Raw):
            src_port = pkt.sport
            if src_port in [80, 443, 8080]:
                query = pkt[DNS].qd.qname.decode("utf-8") if pkt[DNS].qd is not None else "?"
                query = query.rstrip('.')
                if query in self.blocked_sites and query not in self.queries:
                    log = "Alerta gerado pelo seguinte DNS: " + query
                    self.logs.append(log)
                    if len(self.logs) > 100:
                        self.logs.pop(0)
                    send_alert(log)
                    self.queries.add(query)

    def run(self):
        logging("Iniciou do sniffer!")
        sniff(filter='udp port 53', prn=self.sniffer, store=0, count=0)

import keyboard

class Keylogger:
    def __init__(self):
        self.log = ""

    def callback(self, event):
        if event.name == "enter":
            self.report()
        elif event.name == "space":
            self.log += " "
        elif event.name == "backspace":
            self.log = self.log[:-1]
        elif event.name == "caps lock":
            pass  # ignore caps lock key
        else:
            # Get the character that corresponds to the key
            if event.name.startswith("shift"):
                shift_chars = self.get_shift_chars()
                char = shift_chars.get(event.name, "")
            else:
                char = event.name
            self.log += char

    def get_shift_chars(self):
        return {
            "shift + 1": "!",
            "shift + 2": "@",
            "shift + 3": "#",
            "shift + 4": "$",
            "shift + 5": "%",
            "shift + 6": "^",
            "shift + 7": "&",
            "shift + 8": "*",
            "shift + 9": "(",
            "shift + 0": ")",
            "shift + -": "_",
            "shift + =": "+",
            "shift + [": "{",
            "shift + ]": "}",
            "shift + ;": ":",
            "shift + '": "\"",
            "shift + ,": "<",
            "shift + .": ">",
            "shift + /": "?",
            "shift + `": "~",
            "shift + \\": "|",
        }

    def report(self):
        if self.log and (is_hate_speech(self) or is_bad_language(self) or are_malicious_process(self) or verifyng_hate_speech_chatGPT(self.log)):
            logging("Foi enviado o report!")
            send_alert(self.log)
        self.log = ""

    def start(self):
        keyboard.on_release(callback=self.callback)
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
    keylogger = Keylogger()
    keylogger.start()

