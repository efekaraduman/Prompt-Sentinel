# PromptSentinel — Deploy Rehberi

Tahmini süre: **15 dakika**
Maliyet: **Ücretsiz** (Railway + Vercel free tier)

---

## Hazırlanan API Anahtarı

```
PROMPTSENTINEL_API_KEY=<your-api-key>
```
Bu değeri aşağıdaki adımlarda kullanacaksın.

---

## ADIM 1 — GitHub'a yükle

### 1a. GitHub'da yeni repo oluştur
- https://github.com/new git
- Name: `promptsentinel`
- Private seçebilirsin
- **"Add README" işaretleme** — boş olsun
- Create repository

### 1b. Kodu yükle (bu klasörde terminal aç)
```bash
git remote add origin https://github.com/KULLANICI_ADIN/promptsentinel.git
git branch -M main
git push -u origin main
```

---

## ADIM 2 — Backend → Railway

### 2a. Railway hesabı aç
- https://railway.app → "Login with GitHub"

### 2b. Yeni proje oluştur
- "New Project" → "Deploy from GitHub repo"
- `promptsentinel` reposunu seç
- **Root Directory: `.`** (değiştirme)
- Deploy düğmesine bas — otomatik Dockerfile kullanır

### 2c. Environment Variables ekle
Railway Dashboard → projeye tıkla → "Variables" sekmesi → "New Variable":

| KEY | VALUE |
|-----|-------|
| `PROMPTSENTINEL_API_KEY` | `<your-api-key>` |
| `PROMPTSENTINEL_DB_PATH` | `/data/promptsentinel.db` |
| `PROMPTSENTINEL_CORS_ORIGINS` | *(şimdilik boş bırak, Vercel URL'ini sonra ekleyeceksin)* |
| `LOG_LEVEL` | `INFO` |

### 2d. Persistent Volume ekle (veri kaybolmasın)
- Proje ayarları → "Volumes" → "New Volume"
- Mount path: `/data`

### 2e. Backend URL'ini al
- Railway Dashboard → "Deployments" → URL'i kopyala
- Örnek: `https://promptsentinel-production-xxxx.up.railway.app`

---

## ADIM 3 — Frontend → Vercel

### 3a. Vercel hesabı aç
- https://vercel.com → "Continue with GitHub"

### 3b. Projeyi import et
- "Add New Project" → GitHub'dan `promptsentinel` reposunu seç
- **Root Directory: `app/frontend`** (önemli!)
- Framework: Next.js (otomatik algılar)

### 3c. Environment Variable ekle
"Environment Variables" bölümünde:

| KEY | VALUE |
|-----|-------|
| `NEXT_PUBLIC_API_BASE_URL` | Railway'den aldığın URL (örn: `https://promptsentinel-xxx.up.railway.app`) |

### 3d. Deploy et
- "Deploy" düğmesine bas
- 2-3 dakika bekle
- **Frontend URL'ini al** (örn: `https://promptsentinel.vercel.app`)

---

## ADIM 4 — CORS güncelle

Railway'e dön → Variables → `PROMPTSENTINEL_CORS_ORIGINS` değerini güncelle:
```
https://promptsentinel.vercel.app
```
Railway otomatik redeploy yapar.

---

## ADIM 5 — Test kullanıcısına bilgileri gönder

Tester'a şunları gönder:

```
PromptSentinel Test Erişimi
URL: https://promptsentinel.vercel.app

Admin erişimi için:
1. Sağ üstteki "Session" butonuna tıkla
2. API Key: <your-api-key>
3. Enter'a bas

Erişim:
- Testing sayfası: Prompt injection testi
- Dashboard: Scan analytics
- Admin: Kullanıcı yönetimi, sistem analytics
- Trust Center: Güvenlik sertifikaları
- Pricing: Plan bilgileri
```

---

## Sorun giderme

**Backend "Application error"** → Railway → Logs sekmesini kontrol et
**"Invalid API key"** → `PROMPTSENTINEL_API_KEY` env var'ının doğru eklendiğinden emin ol
**CORS hatası** → `PROMPTSENTINEL_CORS_ORIGINS`'in Vercel URL'ini içerdiğinden emin ol
**Veri kayboldu** → Railway Volume mount'unun `/data` olduğunu kontrol et
