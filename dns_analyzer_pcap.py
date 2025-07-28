#!/usr/bin/env python3

import dpkt
import socket
import requests
import json
import time
from prettytable import PrettyTable
from colorama import Fore, Style, init
import os
import sys
from datetime import datetime
import argparse

# Inisialisasi colorama
init(autoreset=True)

# Konfigurasi VirusTotal
VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'  # Ganti dengan API key Anda
VT_URL = 'https://www.virustotal.com/api/v3/domains/'

# Header untuk VirusTotal API
headers = {
    'x-apikey': VT_API_KEY,
    'Accept': 'application/json'
}

def clear_screen():
    """Membersihkan layar konsol"""
    os.system('clear')

def display_banner():
    """Menampilkan banner aplikasi"""
    print(Fore.CYAN + r"""
     ____  _   _ ____    _____                           _             
    |  _ \| \ | / ___|  |_   _| __ __ _ _ __  ___  ___  | |_ ___  _ __ 
    | | | |  \| \___ \    | || '__/ _` | '_ \/ __|/ _ \ | __/ _ \| '__|
    | |_| | |\  |___) |   | || | | (_| | | | \__ \  __/ | || (_) | |   
    |____/|_| \_|____/    |_||_|  \__,_|_| |_|___/\___|  \__\___/|_|   
                                                                       
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 70)
    print(Fore.GREEN + "DNS TRAFFIC ANALYZER (Linux Version)".center(70))
    print(Fore.YELLOW + "=" * 70)
    print(Fore.WHITE + "Tools untuk menganalisis traffic DNS dari file PCAP".center(70))
    print(Fore.WHITE + "Memeriksa indikasi malware/phishing menggunakan VirusTotal".center(70))
    print(Fore.YELLOW + "=" * 70 + Style.RESET_ALL)
    print("\n")

def extract_dns_queries(pcap_file):
    """Mengekstrak query DNS dari file pcap"""
    dns_queries = {}
    
    try:
        with open(pcap_file, 'rb') as f:
            # Handle both pcap and pcapng files
            try:
                pcap = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)
            
            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.udp.UDP):
                        continue
                    
                    udp = ip.data
                    if udp.dport == 53:  # DNS query
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            if dns.qr == dpkt.dns.DNS_Q:  # Only queries
                                for q in dns.qd:
                                    query = q.name.lower()
                                    if query not in dns_queries:
                                        dns_queries[query] = {
                                            'count': 1,
                                            'first_seen': timestamp,
                                            'last_seen': timestamp,
                                            'src_ip': socket.inet_ntoa(ip.src)
                                        }
                                    else:
                                        dns_queries[query]['count'] += 1
                                        dns_queries[query]['last_seen'] = timestamp
                        except:
                            continue
                except:
                    continue
                    
    except FileNotFoundError:
        print(Fore.RED + "[ERROR] File PCAP tidak ditemukan!")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Gagal memproses file PCAP: {str(e)}")
        sys.exit(1)
        
    return dns_queries

def check_virustotal(domain):
    """Memeriksa reputasi domain di VirusTotal"""
    try:
        response = requests.get(VT_URL + domain, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None
        else:
            print(Fore.YELLOW + f"[WARNING] VirusTotal API error (HTTP {response.status_code}) untuk domain: {domain}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(Fore.YELLOW + f"[WARNING] Gagal mengakses VirusTotal untuk domain {domain}: {str(e)}")
        return None

def analyze_domains(dns_queries, max_domains=50):
    """Menganalisis domain menggunakan VirusTotal"""
    results = []
    total_domains = min(len(dns_queries), max_domains)  # Limit domains to check
    processed = 0
    
    # Sort by query count (descending)
    sorted_domains = sorted(dns_queries.items(), key=lambda x: x[1]['count'], reverse=True)
    
    print(Fore.CYAN + "\nMemulai analisis dengan VirusTotal...")
    print(Fore.WHITE + f"Total domain yang akan diperiksa: {total_domains} (top {max_domains} by query count)\n")
    
    for domain, data in sorted_domains[:max_domains]:
        processed += 1
        print(Fore.WHITE + f"\rMemproses: {processed}/{total_domains} - {domain.ljust(50)}", end="")
        
        vt_result = check_virustotal(domain)
        
        if vt_result:
            stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            reputation = vt_result.get('data', {}).get('attributes', {}).get('reputation', 0)
            categories = vt_result.get('data', {}).get('attributes', {}).get('categories', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            # Klasifikasi hasil dengan threshold lebih ketat
            status = "Clean"
            if malicious >= 3:  # Minimal 3 vendor menganggap malicious
                status = "Malicious"
            elif malicious > 0 or suspicious >= 2:
                status = "Suspicious"
            elif reputation < -10:  # Hanya anggap low reputation jika sangat negatif
                status = "Low Reputation"
                
            if status != "Clean":
                results.append({
                    'domain': domain,
                    'status': status,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'reputation': reputation,
                    'count': data['count'],
                    'src_ip': data.get('src_ip', 'N/A'),
                    'first_seen': datetime.fromtimestamp(data['first_seen']).strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': datetime.fromtimestamp(data['last_seen']).strftime('%Y-%m-%d %H:%M:%S'),
                    'categories': ', '.join(categories.values()) if categories else 'N/A',
                    'vt_link': f"https://www.virustotal.com/gui/domain/{domain}"
                })
        
        # Jeda untuk menghindari rate limit (4 requests/min untuk API gratis)
        if processed < total_domains:
            time.sleep(15)  # 15 detik = 4 requests/min
    
    print("\n" + Fore.GREEN + "Analisis selesai!\n")
    return results

def generate_report(results, output_file=None):
    """Membuat laporan hasil analisis"""
    if not results:
        print(Fore.GREEN + "Tidak ditemukan indikasi malware atau phishing pada traffic DNS.")
        return
    
    # Buat tabel hasil
    table = PrettyTable()
    table.field_names = [
        "Domain",
        "Status",
        "Malicious",
        "Suspicious",
        "Reputation",
        "Count",
        "Source IP",
        "Categories"
    ]
    
    table.align = "l"
    
    for result in results:
        # Warna status
        status_color = Fore.RED if result['status'] == "Malicious" else Fore.YELLOW if result['status'] == "Suspicious" else Fore.MAGENTA
        
        table.add_row([
            Fore.CYAN + result['domain'],
            status_color + result['status'],
            Fore.RED + str(result['malicious']) if result['malicious'] > 0 else Fore.GREEN + str(result['malicious']),
            Fore.YELLOW + str(result['suspicious']) if result['suspicious'] > 0 else Fore.GREEN + str(result['suspicious']),
            Fore.GREEN + str(result['reputation']) if result['reputation'] >= 0 else Fore.RED + str(result['reputation']),
            Fore.WHITE + str(result['count']),
            Fore.WHITE + result['src_ip'],
            Fore.WHITE + result.get('categories', 'N/A')
        ])
    
    print(table)
    
    # Ringkasan statistik
    print(Fore.YELLOW + "\nSUMMARY:")
    print(Fore.YELLOW + "=" * 80)
    
    stats = {
        "Malicious": 0,
        "Suspicious": 0,
        "Low Reputation": 0
    }
    
    for r in results:
        stats[r['status']] += 1
    
    print(Fore.RED + f"Malicious Domains: {stats['Malicious']}")
    print(Fore.YELLOW + f"Suspicious Domains: {stats['Suspicious']}")
    print(Fore.MAGENTA + f"Low Reputation Domains: {stats['Low Reputation']}")
    print(Fore.YELLOW + "=" * 80 + "\n")
    
    # Jika output file ditentukan
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write("DNS Traffic Analysis Report\n")
                f.write("="*50 + "\n\n")
                f.write(str(table) + "\n\n")
                f.write("SUMMARY:\n")
                f.write("="*50 + "\n")
                f.write(f"Malicious Domains: {stats['Malicious']}\n")
                f.write(f"Suspicious Domains: {stats['Suspicious']}\n")
                f.write(f"Low Reputation Domains: {stats['Low Reputation']}\n\n")
                f.write("Detailed Links:\n")
                for r in results:
                    f.write(f"- {r['domain']}: {r['vt_link']}\n")
            
            print(Fore.GREEN + f"\nReport tersimpan di: {output_file}")
        except Exception as e:
            print(Fore.RED + f"Gagal menyimpan report: {str(e)}")

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='DNS Traffic Analyzer for Linux')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('-o', '--output', help='Output file untuk menyimpan report')
    parser.add_argument('-l', '--limit', type=int, default=50, 
                       help='Limit jumlah domain yang diperiksa (default: 50)')
    args = parser.parse_args()
    
    clear_screen()
    display_banner()
    
    print(Fore.WHITE + f"Memproses file PCAP: {args.pcap_file}\n")
    
    # Ekstrak query DNS
    print(Fore.CYAN + "Mengekstrak query DNS dari file PCAP..." + Style.RESET_ALL)
    dns_queries = extract_dns_queries(args.pcap_file)
    
    if not dns_queries:
        print(Fore.YELLOW + "Tidak ditemukan query DNS dalam file PCAP.")
        sys.exit(0)
    
    print(Fore.GREEN + f"Berhasil mengekstrak {len(dns_queries)} domain unik dari traffic DNS.\n")
    
    # Analisis dengan VirusTotal
    results = analyze_domains(dns_queries, args.limit)
    
    # Tampilkan hasil dan simpan ke file jika diperlukan
    generate_report(results, args.output)
    
    print(Fore.GREEN + "\nAnalisis selesai. Gunakan link VirusTotal untuk verifikasi manual.")
    print(Fore.YELLOW + "Untuk mengurangi false positive, hanya domain dengan minimal 3 deteksi malicious yang diklasifikasikan sebagai berbahaya.\n")

if __name__ == "__main__":
    # Check dependencies
    try:
        import dpkt
        import requests
        import prettytable
        import colorama
    except ImportError as e:
        print(Fore.RED + f"Error: Modul Python yang diperlukan tidak ditemukan: {str(e)}")
        print(Fore.YELLOW + "Instal dengan: pip install dpkt requests prettytable colorama")
        sys.exit(1)
    
    main()
