import streamlit as str_web
import json
from urllib.parse import urlparse, parse_qs

# Sayfa ayarları
str_web.set_page_config(page_title="Mehmet Kerem - HAR Analyzer", layout="wide", initial_sidebar_state="collapsed")

# --- 🌓 GECE / GÜNDÜZ MODU MANTIĞI ---
if "theme_mode" not in str_web.session_state:
    str_web.session_state.theme_mode = "dark"

# Sağ üst köşe için buton düzeni (Header Alanı)
head_col1, head_col2 = str_web.columns([9, 1])

with head_col1:
    str_web.markdown("<h2 style='color: #ffffff; margin-top: 0; font-family: sans-serif; font-weight: bold;'>Mehmet Kerem<span style='color: #00e5ff;'>.</span></h2>", unsafe_allow_html=True)

with head_col2:
    if str_web.session_state.theme_mode == "dark":
        if str_web.button("🌙"):
            str_web.session_state.theme_mode = "light"
            str_web.rerun()
    else:
        if str_web.button("☀️"):
            str_web.session_state.theme_mode = "dark"
            str_web.rerun()

# --- 🎨 ÖZEL CSS TEMA ENJEKSİYONU ---
if str_web.session_state.theme_mode == "dark":
    theme_css = """
    <style>
        .stApp { background-color: #0a0a0a; color: #ffffff; }
        h1, h2, h3, p, span, label { color: #ffffff !important; }
        .stMarkdown p { color: #aaaaaa !important; }
        
        div[data-testid="stFileUploader"] {
            background-color: #111111 !important;
            border: 1px solid #222222 !important;
            border-radius: 8px;
            padding: 20px;
        }
        div[data-testid="stFileUploadDropzone"] {
            background-color: #1a1a1a !important;
            border: 1px dashed #333333 !important;
        }
        /* Gece modunda iç kutudaki her şey beyaz */
        div[data-testid="stFileUploadDropzone"] *, 
        div[data-testid="stFileUploadDropzone"] span, 
        div[data-testid="stFileUploadDropzone"] small,
        div[data-testid="stFileUploadDropzone"] button,
        div[data-testid="stFileUploadDropzone"] svg,
        div[data-testid="stFileUploadDropzone"] path { 
            color: #ffffff !important; 
            fill: #ffffff !important; 
        }
        
        div[data-testid="stMetricValue"] { color: #00e5ff !important; font-weight: bold; }
        div[data-testid="stMetricLabel"] { color: #888888 !important; }
        .stTable { background-color: #111111 !important; color: #ffffff !important; border-radius: 8px; }
        button[data-baseweb="tab"] { color: #888888 !important; }
        button[aria-selected="true"] { color: #00e5ff !important; border-bottom-color: #00e5ff !important; }
    </style>
    """
else:
    # GÜNDÜZ MODU
    theme_css = """
    <style>
        .stApp { background-color: #ffffff; color: #111111; }
        h1, h3, p, span, label { color: #111111 !important; }
        h2 { color: #111111 !important; }
        h2 span { color: #00b4d8 !important; }
        
        div[data-testid="stFileUploader"] {
            background-color: #ffffff !important;
            border: 1px solid #dee2e6 !important;
            border-radius: 8px;
            padding: 20px;
        }
        /* Fotoğraftaki koyu iç kutu */
        div[data-testid="stFileUploadDropzone"] {
            background-color: #212529 !important; 
            border: none !important;
        }
        
        /* İNATÇI SİYAH YAZILARI BEYAZA EZEN KISIM */
        div[data-testid="stFileUploader"] section *,
        div[data-testid="stFileUploader"] p,
        div[data-testid="stFileUploader"] span,
        div[data-testid="stFileUploader"] small { 
            color: #ffffff !important; 
        }
        div[data-testid="stFileUploader"] svg, 
        div[data-testid="stFileUploader"] path { 
            fill: #ffffff !important; 
        }
        div[data-testid="stFileUploader"] button { 
            color: #ffffff !important; 
            border: 1px solid #555555 !important; 
        }
        
        div[data-testid="stMetricValue"] { color: #00b4d8 !important; }
        button[aria-selected="true"] { color: #00b4d8 !important; border-bottom-color: #00b4d8 !important; }
    </style>
    """

str_web.markdown(theme_css, unsafe_allow_html=True)

# --- 🚀 ANA TASARIM ---
str_web.markdown("<br><br>", unsafe_allow_html=True)
str_web.markdown("<center><div style='background-color: #1a1a1a; color: #00e5ff; padding: 4px 16px; border-radius: 20px; display: inline-block; font-size: 12px; font-weight: bold; letter-spacing: 1px;'>🔵 HAR GÜVENLİK DENETİM ARACI</div></center>", unsafe_allow_html=True)
str_web.markdown("<h1 style='text-align: center; font-size: 50px; font-weight: 800; margin-bottom: 10px;'>HAR Security Audit.</h1>", unsafe_allow_html=True)
str_web.markdown("<p style='text-align: center; font-size: 16px; margin-bottom: 40px;'>HTTP Archive (HAR) dosyalarındaki zayıf parametreleri, sızan token'ları, güvensiz çerezleri<br>ve eksik güvenlik başlıklarını otomatik tespit edin.</p>", unsafe_allow_html=True)

# Dosya yükleme alanı
uploaded_file = str_web.file_uploader("HAR Dosyası Yükle", type=["har"], label_visibility="collapsed")

str_web.markdown("<br><br>", unsafe_allow_html=True)

# --- 🔍 ANALİZ MOTORU ---
if uploaded_file is not None:
    try:
        har_data = json.load(uploaded_file)
        entries = har_data.get('log', {}).get('entries', [])
        
        str_web.success(f"✔️ Analiz Başarılı! Toplam {len(entries)} ağ isteği tarandı.")
        
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
            
            # 1. URL Kontrolü
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for param in query_params:
                if any(kw in param.lower() for kw in suspected_keywords):
                    url_token_findings.append({"Metot": method, "Path": urlparse(url).path, "Sızan Parametre": param})

            # 2. Çerez Kontrolü
            cookies = response.get('cookies', [])
            for cookie in cookies:
                c_name = cookie.get('name', '')
                if not cookie.get('httpOnly', False) or not cookie.get('secure', False):
                    status = []
                    if not cookie.get('httpOnly', False): status.append("HttpOnly Eksik")
                    if not cookie.get('secure', False): status.append("Secure Eksik")
                    insecure_cookie_findings.append({"Çerez Adı": c_name, "Sorun": " & ".join(status)})

            # 3. Başlık Kontrolü
            headers_dict = {h.get('name', '').lower(): h.get('value', '') for h in response.get('headers', [])}
            if 'text/html' in headers_dict.get('content-type', '') or 'application/json' in headers_dict.get('content-type', ''):
                missing_for_this = [sh for sh in security_headers if sh.lower() not in headers_dict]
                if missing_for_this:
                    missing_header_findings.append({"URL / API Endpoint": url.split('?')[0], "Eksik Başlıklar": ", ".join(missing_for_this)})

        # Metrik Skor Kutuları
        col1, col2, col3 = str_web.columns(3)
        with col1:
            str_web.metric("Sızan Parametre", len(set(f"{x['Path']}{x['Sızan Parametre']}" for x in url_token_findings)))
        with col2:
            str_web.metric("Güvensiz Çerez", len(set(x['Çerez Adı'] for x in insecure_cookie_findings)))
        with col3:
            str_web.metric("Zafiyetli API / Sayfa", len(set(x['URL / API Endpoint'] for x in missing_header_findings)))

        str_web.divider()

        # Sonuç Sekmeleri
        tab1, tab2, tab3 = str_web.tabs(["🚨 URL Sızıntıları", "🍪 Çerez Zafiyetleri", "🛡️ Eksik Güvenlik Başlıkları"])

        with tab1:
            if url_token_findings:
                str_web.table(url_token_findings[:15])
            else:
                str_web.success("URL parametre sızıntısı bulunamadı.")

        with tab2:
            if insecure_cookie_findings:
                unique_cookies = [dict(t) for t in {tuple(d.items()) for d in insecure_cookie_findings}]
                str_web.table(unique_cookies[:15])
            else:
                str_web.success("Tüm çerezler güvende.")

        with tab3:
            if missing_header_findings:
                unique_headers = [dict(t) for t in {tuple(d.items()) for d in missing_header_findings}]
                str_web.table(unique_headers[:15])
            else:
                str_web.success("Güvenlik başlıkları eksiksiz.")

    except Exception as e:
        str_web.error(f"Hata: {e}")