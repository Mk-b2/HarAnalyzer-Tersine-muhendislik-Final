# 🚨 HAR Security Audit Tool

Bu proje, web tarayıcılarından veya mobil cihazlardan dışa aktarılan **HTTP Archive (HAR)** dosyalarını analiz ederek potansiyel siber güvenlik zafiyetlerini ve veri sızıntılarını tespit eden, Streamlit tabanlı modern bir web dashboard aracıdır.

---

## ✨ Özellikler

* **Kullanıcı Dostu Arayüz:** Modern, karanlık tema odaklı ve sürükle-bırak destekli web paneli.
* **Gece / Gündüz Modu:** Tek tıkla değiştirilebilen ve tam uyumlu renk paletleri.
* **Hızlı Analiz:** Yüzlerce ağ isteğini saniyeler içinde ayrıştırır ve görselleştirir.
* **Yerel Çalışma:** Verileriniz hiçbir sunucuya gönderilmez, tüm analiz tarayıcınızda ve yerel makinenizde gerçekleşir.

---

## ⚙️ Güvenlik Motoru Nasıl Çalışır? (Core Logic)

Araç, yüklenen HAR dosyasının JSON ağacını `log -> entries -> request/response` yoluyla ayrıştırır ve her bir ağ isteğini 3 ana güvenlik filtresinden geçirir:

### 1. URL Parametre Sızıntısı (Token Avcılığı)
GET veya POST isteklerinin URL'leri `urllib.parse` ile parçalanır. Query parametreleri incelenerek şifrelenmesi gereken hassas verilerin (örn: `token`, `auth`, `api_key`, `jwt`, `password`) URL üzerinde açıkça taşınıp taşınmadığı kontrol edilir. URL'de sızan veriler loglarda saklanabileceği için kritik bir zafiyettir.

### 2. Güvensiz Çerez Tespiti (Cookie Security)
Sunucudan dönen yanıtlar (Responses) içindeki `Set-Cookie` başlıkları taranır. Her bir çerez için tarayıcı güvenlik bayrakları kontrol edilir:
* **HttpOnly Eksikliği:** Çerezin JavaScript (XSS) ile çalınmaya açık olduğunu belirtir.
* **Secure Eksikliği:** Çerezin şifresiz (HTTP) ağlarda dinlenebileceğini belirtir.

### 3. Eksik Güvenlik Başlıkları (Security Headers)
Arka planda çalışan API'ler (`application/json`) ve web sayfaları (`text/html`) taranır. Modern tarayıcıları siber saldırılardan koruyan aşağıdaki kritik başlıkların sunucu yanıtında olup olmadığı denetlenir:
* `Strict-Transport-Security` (HSTS)
* `Content-Security-Policy` (CSP)
* `X-Frame-Options` (Clickjacking Koruması)
* `X-Content-Type-Options` (MIME Sniffing Koruması)

---

## 🚀 Kurulum ve Çalıştırma

Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyin:

**1. Gerekli kütüphaneyi yükleyin:**
```bash
pip install streamlit