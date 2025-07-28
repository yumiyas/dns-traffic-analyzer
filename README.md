 <b>DNS Traffic Analyzer</b> 🔍

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
echo "VT_API_KEY='your_api_key_here'" > dns_analyzer_pcap.py
chmod +x dns_analyzer_pcap.py
```
Windows
```powershell
git clone https://github.com/yumiyas/dns-traffic-analyzer.git
cd dns-traffic-analyzer
pip install -r requirements.txt
echo VT_API_KEY='your_api_key_here' > dns_analyzer_pcap.py
```
## 🛠 Penggunaan
Basic Command
```bash
./dns_analyzer_pcap.py test.pcap
```
### 🔧 Opsi Lanjutan

| Opsi | Deskripsi                              | Contoh           |
|------|----------------------------------------|------------------|
| `-o FILE` | Simpan output ke file               | `-o report.txt`  |
| `-l LIMIT`| Batasi jumlah domain diperiksa (default: 50) | `-l 30`          |
| `-v`      | Mode verbose (tampilkan detail proses) | `-v`           |
| `-q`      | Mode quiet (output minimal)          | `-q`             |

## 📝 Contoh Output
# 🛡️ DNS Traffic Analysis Report  
**Timestamp**: 2025-07-28 09:20:19  

## 📊 Summary
- **Total domains analyzed**: 142  
- **Threats detected**: 3  
- **Analysis duration**: 2.4 seconds  

## 🔍 Threat Details
| Domain            | Status     | Detections | Confidence |
|-------------------|------------|------------|------------|
| `malware-c2.com`  | 🔴 MALICIOUS | 23/68      | 98%        |
| `phishing-site.net` | 🟡 SUSPICIOUS | 5/68       | 75%        |
| `shady-domain.org`  | 🟠 LOW REP   | -          | 40%        |

## 📌 Legend
- 🔴 MALICIOUS: Dideteksi >5 vendor keamanan  
- 🟡 SUSPICIOUS: 1-5 deteksi vendor  
- 🟠 LOW REP: Reputasi negatif tanpa deteksi
## 📜 Lisensi
<div align="center">
  
---

**MIT © 2025 Yumiyas**  
Dibuat dengan ❤️ untuk keamanan jaringan yang lebih baik  

</div>
