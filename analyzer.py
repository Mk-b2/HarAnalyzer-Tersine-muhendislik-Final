import argparse
import json
import sys
from urllib.parse import urlparse, parse_qs

def analyze_har(har_data, export_path=None):
    print("\n[+] --- GÜVENLİK TARAMASI BAŞLATILDI ---")
    
    entries = har_data.get('log', {}).get('entries', [])
    if not entries:
        print("[-] Dosya içinde hiç ağ isteği bulunamadı.")
        return

    url_token_findings = []
    insecure_cookie_findings = []
    missing_header_findings = []
    
    suspected_keywords = ['token', 'auth', 'key', 'api_key', 'jwt', 'session', 'secret', 'password']
    security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']

    for entry in entries:
        request = entry.get('request', {})
        response = entry.get('response', {})
        url = request.get('url', '')
        method = request.get('method', '')
        
        # --- 1. URL PARAMETRE KONTROLÜ ---
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param in query_params:
            if any(kw in param.lower() for kw in suspected_keywords):
                url_token_findings.append(f"[{method}] {urlparse(url).path} -> Sızan Parametre: '{param}'")

        # --- 2. GÜVENSİZ ÇEREZ KONTROLÜ ---
        cookies = response.get('cookies', [])
        for cookie in cookies:
            c_name = cookie.get('name', '')
            is_http_only = cookie.get('httpOnly', False)
            is_secure = cookie.get('secure', False)
            
            if not is_http_only or not is_secure:
                flags = []
                if not is_http_only: flags.append("HttpOnly Eksik")
                if not is_secure: flags.append("Secure Eksik")
                insecure_cookie_findings.append(f"Çerez: '{c_name}' -> Durum: {', '.join(flags)}")

        # --- 3. EKSİK GÜVENLİK BAŞLIKLARI KONTROLÜ ---
        headers_dict = {h.get('name', '').lower(): h.get('value', '') for h in response.get('headers', [])}
        content_type = headers_dict.get('content-type', '')
        
        if 'text/html' in content_type:
            missing_for_this = []
            for sec_header in security_headers:
                if sec_header.lower() not in headers_dict:
                    missing_for_this.append(sec_header)
            
            if missing_for_this:
                clean_url = url.split('?')[0]
                missing_header_findings.append(f"URL: {clean_url} -> Eksik: {', '.join(missing_for_this)}")

    # Ekrana basma işlemleri (Benzersiz hale getirerek)
    unique_tokens = list(set(url_token_findings))
    unique_cookies = list(set(insecure_cookie_findings))
    unique_headers = list(set(missing_header_findings))

    print("\n🚨 KISIM 1: URL'DE SIZAN HASSAS PARAMETRELER / TOKEN'LAR")
    if unique_tokens:
        for finding in unique_tokens[:10]: print(f"  [!] {finding}")
    else: print("  [+] Temiz! URL parametrelerinde hassas bir veriye rastlanmadı.")

    print("\n🍪 KISIM 2: GÜVENSİZ ÇEREZLER (SET-COOKIE)")
    if unique_cookies:
        for finding in unique_cookies[:10]: print(f"  [!] {finding}")
    else: print("  [+] Temiz! Tüm çerezlerin HttpOnly ve Secure bayrakları aktif.")

    print("\n🛡️ KISIM 3: EKSİK GÜVENLİK BAŞLIKLARI (SECURITY HEADERS)")
    if unique_headers:
        for finding in unique_headers[:5]: print(f"  [!] {finding}")
    else: print("  [+] Mükemmel! İncelenen HTML yanıtlarında tüm güvenlik başlıkları tam.")

    # --- 💾 DISA AKTARMA (EXPORT) MANTIĞI ---
    if export_path:
        report_data = {
            "summary": {
                "total_leak_parameters": len(unique_tokens),
                "total_insecure_cookies": len(unique_cookies),
                "total_missing_headers": len(unique_headers)
            },
            "findings": {
                "url_token_leaks": unique_tokens,
                "insecure_cookies": unique_cookies,
                "missing_security_headers": unique_headers
            }
        }
        with open(export_path, 'w', encoding='utf-8') as rf:
            json.dump(report_data, rf, indent=4, ensure_ascii=False)
        print(f"\n[📊] Rapor başarıyla kaydedildi: {export_path}")

def main():
    parser = argparse.ArgumentParser(description="HAR Dosyası Güvenlik ve Ağ Analiz aracı")
    parser.add_argument("-f", "--file", required=True, help="Analiz edilecek HAR dosyasının yolu")
    # Yeni eklenen çıktı parametresi (İsteğe bağlı)
    parser.add_argument("-o", "--output", required=False, help="Raporun kaydedileceği JSON dosya adı")
    
    args = parser.parse_args()
    har_file_path = args.file

    print(f"[*] Analiz başlatılıyor: {har_file_path}")

    try:
        with open(har_file_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
            print("[+] HAR dosyası başarıyla okundu ve belleğe yüklendi!")
            analyze_har(har_data, export_path=args.output)
            
    except FileNotFoundError:
        print(f"[-] HATA: '{har_file_path}' adında bir dosya bulunamadı.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[-] HATA: Belirtilen dosya geçerli bir JSON formatında değil.")
        sys.exit(1)

if __name__ == "__main__":
    main()