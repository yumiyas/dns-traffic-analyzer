# DNS Traffic Analyzer 🔍

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub Stars](https://img.shields.io/github/stars/yumiyas/dns-traffic-analyzer)

Tools canggih untuk analisis traffic DNS dan deteksi aktivitas mencurigakan dari file PCAP dengan integrasi VirusTotal.

## 🌟 Fitur Utama

- 🕵️‍♂️ Analisis traffic DNS (PCAP/PCAPNG)
- 🔗 Integrasi real-time dengan VirusTotal API
- 🚨 Deteksi otomatis domain malicious & phishing
- 🎨 Tampilan hasil berwarna & interaktif
- 📊 Pembuatan laporan otomatis (TXT/JSON)
- ⚖️ Threshold ketat untuk minimalisasi false positive

## 📦 Prasyarat

- Python 3.6+
- VirusTotal API key ([Dapatkan gratis](https://www.virustotal.com/))
- Dependencies:
  ```bash
  dpkt requests prettytable colorama
  ```

## 🚀 Instalasi
Linux/macOS
```bash
git clone https://github.com/yumiyas/dns-traffic-analyzer.git
cd dns-traffic-analyzer
pip install -r requirements.txt
echo "VT_API_KEY='your_api_key_here'" > config.py
chmod +x dns_analyzer.py
```
Windows
```powershell
git clone https://github.com/yumiyas/dns-traffic-analyzer.git
cd dns-traffic-analyzer
pip install -r requirements.txt
echo VT_API_KEY='your_api_key_here' > config.py
```
