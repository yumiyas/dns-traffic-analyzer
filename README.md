DNS Traffic Analyzer 🔍
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)](#)
[![GitHub](https://img.shields.io/badge/GitHub-%23121011.svg?logo=github&logoColor=white)](#)

DNS Traffic Analyzer adalah tools yang diuat  untuk mendeteksi aktivitas mencurigakan dalam traffic DNS dari file PCAP. 
Dilengkapi integrasi VirusTotal dan analisis cerdas untuk identifikasi malware/phishing.
🌟 Fitur Utama

    ✅ Analisis traffic DNS dari file PCAP/PCAPNG

    ✅ Integrasi dengan VirusTotal API

    ✅ Deteksi domain malicious & phishing

    ✅ Tampilan hasil berwarna & interaktif

    ✅ Pembuatan laporan otomatis

    ✅ Threshold ketat untuk minimalisasi false positive

🚀 Persyaratan Instalasi

    Python 3.6+

    VirusTotal API key (gratis)

Langkah Instalasi

Clone repository
git clone https://github.com/yourusername/dns-traffic-analyzer.git
cd dns-traffic-analyzer
pip install -r requirements.txt
chmod +x



echo "VT_API_KEY='your_virustotal_api_key'" > config.py

🛠 Penggunaan
Basic Command
bash

python dns_analyzer.py capture.pcap

Opsi Lanjutan
Opsi	Deskripsi	Contoh
-o FILE	Simpan output ke file	-o report.txt
-l LIMIT	Batasi jumlah domain diperiksa	-l 30
-v	Mode verbose	-v
-q	Mode quiet (minimal output)	-q
Contoh Output
text

==============================================
🛡️  DNS TRAFFIC ANALYSIS REPORT
==============================================
🔎 Total domains analyzed: 142
⚠️  Threats detected: 3

+------------------------------+----------+------------+
| Domain                       | Status   | Detections |
+------------------------------+----------+------------+
| malware-c2.com               | 🔴 MAL   | 23/68      |
| phishing-site.net            | 🟡 SUS   | 5/68       |
| shady-domain.org             | 🟠 LOW   | -          |
+------------------------------+----------+------------+

📁 Struktur File
text

dns-traffic-analyzer/
├── dns_analyzer.py    # Main script
├── config.py          # Konfigurasi API
├── samples/           # Contoh file PCAP
│   ├── clean.pcap
│   └── malware.pcap
└── reports/           # Laporan otomatis

🛠️ Development
bash

# Setup environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Run tests
python -m unittest discover tests

🤝 Kontribusi

Pull request dipersilakan! Untuk perubahan besar, buka issue terlebih dahulu.
📜 Lisensi

MIT © 2025 Yumiyas
<div align="center"> <sub>Dibuat dengan ❤️ untuk keamanan jaringan yang lebih baik</sub> </div>

