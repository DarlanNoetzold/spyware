# spyware

## Desenvolvimento:
* Foi usado Python 3.8 como linguagem base;
* Foram usado bibliotecas auxiliares para extração dos dados (Keyboard, getmac, psutil, base64, io, pyscreenshot e IPy);
* Para salvar os dados foi usado uma API, desenvolvida por mim e hospedada na Heroku;
* Para o envio dos dados foi usada a bilioteca requests e para a serialização foi usada a biblioteca json;

## Projeto:
* Projeto de Prova de conceito para o desenvolvimento de malware's para que assim possamos aprender como evitá-los e reconhece-los;
* Este spyware faz parte de um projeto maior chamado Remote-Analyser, o qual é um sistema desenvolvido por mim, para coleta de dados suspeitos em computadores empresarias e/ou institucionais. Servindo assim, como um monitoramento mais eficiente do patrimônio destas entidades;
* Esse script que coleta os dados foi desenvolvido em Python usando diversas bibliotecas específicas para auxiliar no desenvolvimento. Esse script fica ativo e vai gerar um Alerta toda vez que algo suspeito seja digitado, se algum processo malicioso esteja rodando ou se tem alguma porta aberta com alguma aplicação suspeita, enviando os dados para a API Gateway. Os dados coletados são: o endereço MAC do PC, a frase digitada que gerou o Alerta, os processos ativos no sistema e um PrintScreen da tela do usuário. Após isso, o script faz login na API Gateway e usa o token gerado para salvar os dados na API.

## Como utilizar:
* Primeiramente é preciso baixar o projeto e rodar o comando:
```
python setup.py build
```
* Este comando vai compilar o projeto, gerando um projeto com um .exe;
* Copie a pasta com o .exe e cole em um diretório chamado keyLogger;
* Esta pasta deve ser colocada no diretório raiz do seu SO;
* Após isso basta ir para o diretório C:\Users\<Seu Usuário>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup;
* E colar o arquivo .vbs:
<br>
Link: https://github.com/DarlanNoetzold/spyware/blob/main/spyware/script_background.vbs
* Agora, o script será executado toda vez que o windows iniciar, sem precisar ter as biblioteas usadas, nem o Python.

---
## API:
* A API:
<br>Link: https://spyware-api.herokuapp.com/
* Documentação da API:
<br>Link: https://spyware-api.herokuapp.com/swagger-ui/index.html
* Repositório no GitHub:
<br>Link: https://github.com/DarlanNoetzold/spyware-API

---
## API do HateSpeech:
* A API:
<br>Link: https://hate-speech-portuguese.herokuapp.com
* Repositório no GitHub:
<br>Link: https://github.com/DarlanNoetzold/HateSpeech-portuguese

---
## Remote-Analyser
* Repositório no GitHub:
<br>Link: https://github.com/DarlanNoetzold/Remote-Analyser
* Heroku:
<br>Link: https://remoteanalyser.herokuapp.com/home

---
⭐️ From [DarlanNoetzold](https://github.com/DarlanNoetzold)
