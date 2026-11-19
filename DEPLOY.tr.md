# ssh-honeypot'u bir VPS'e kurmak

🇬🇧 [English](DEPLOY.md)

Bu rehber Ubuntu 24.04 (veya Debian 12) kullanan bir VPS varsayar ve zor
durum için yazıldı: **aynı zamanda production (canlı) bir web sitesi ve mail
sunucusu çalıştıran** bir sunucu. Ayrı, gözden çıkarılabilir bir VPS'te de
aynı adımlar çalışır; sadece kaybedecek daha az şeyin olur.

Linux'ta yeniysen endişelenme: her komutun yanında (veya hemen altında) ne
yaptığını anlatan kısa bir açıklama var. `#` ile başlayan kısımlar yorumdur,
onları yazmana gerek yok. `sudo` "bu komutu yönetici (root) olarak çalıştır"
demektir ve senden kendi parolanı isteyebilir.

| Honeypot'un yaptığı | Yapmadığı |
|---|---|
| TCP 2222 portunu dinler ve SSH giriş denemelerini kaydeder | sshd'yi, nginx'i, güvenlik duvarını, mail'i veya başka bir servisi asla değiştirmez |
| kendi SQLite veritabanını ve `/var/log/ssh-honeypot/auth.log` dosyasını yazar | saldırgan komutlarını asla çalıştırmaz, hiçbir şey indirmez |
| isteğe bağlı olarak `api.telegram.org` adresine HTTPS istekleri gönderir | root olarak çalışmaz, hiçbir capability'si (özel yetkisi) yoktur |
| en fazla bir CPU çekirdeğinin %25'ini ve 256 MB RAM kullanır (zorunlu sınırlar) | dashboard'u internete açmaz (yalnızca `127.0.0.1`) |

> **Başlamadan önce: bu gerçekten production'ın yanında çalışmalı mı?**
> İzolasyon gerçek (gerçek shell yok, capability yok, sandbox var,
> production dizinleri gizli, kaynak sınırları var), ama honeypot yine de
> yabancıların konuştuğu bir kod ve web sitenle, mail sunucunla aynı
> çekirdeği (kernel) ve aynı IP adresini paylaşıyor. **Yapabiliyorsan ayrı ve
> ucuz bir VPS kullan.** Production sunucusunu kullanacaksan varsayılan
> `reject` politikasını ve aşağıdaki (a) seçeneğini koru. Ayrıntılı tartışma
> [README: Production'ın yanında çalıştırmalı mısın?](README.tr.md#productionın-yanında-çalıştırmalı-mısın)
> bölümünde.

---

## 0. Hazırlık

1. **Sistemi güncelle** ve güvenlik güncellemelerinin otomatik kurulmasını
   sağla. Sandbox, çekirdeği diğer her şeyle paylaşır; bu yüzden güncel bir
   çekirdek önemli.

   ```bash
   sudo apt update && sudo apt upgrade     # paket listesini yeniler ve kurulu paketleri günceller
   sudo apt install unattended-upgrades    # güvenlik güncellemelerini otomatik kuran aracı yükler
   ```

2. **2222 portunun boş olduğunu kontrol et:**

   ```bash
   sudo ss -ltnp 'sport = :2222'           # 2222'yi dinleyen bir program var mı gösterir; çıktı yoksa port boştur
   ```

3. **Güvenlik duvarını (firewall) tanı.** Hiçbir şeyi değiştirmeden önce
   gerçek SSH portuna izin verildiğinden emin ol, yoksa kendini dışarıda
   bırakabilirsin:

   ```bash
   sudo ufw status verbose                 # ufw güvenlik duvarının açık olup olmadığını ve kurallarını listeler
   ```

   Birçok VPS sağlayıcısının web panelinde ayrıca bir güvenlik duvarı veya
   "security group" bulunur. 2222 portuna orada da izin verilmeli.

4. (İsteğe bağlı) **Telegram:** Telegram'da `@BotFather` ile konuş, `/newbot`
   gönder ve verdiği token'ı kopyala. Botuna herhangi bir mesaj gönder, sonra
   tarayıcında `https://api.telegram.org/bot<TOKEN>/getUpdates` adresini aç
   ve `chat.id` değerini kopyala. Bildirim yalnızca bir oturum sahte shell'e
   ulaştığında gönderilir; varsayılan `reject` politikasında hiç bildirim
   gelmez.

5. (İsteğe bağlı) **GeoIP:** README'deki "GeoIP" bölümüne bak. Veritabanı
   yoksa ülkeler "unknown" (bilinmiyor) görünür.

---

## 1. Saldırganların honeypot'a nasıl ulaşacağını seç

Honeypot her zaman **2222** portunu dinler. Bu ayrıcalıksız (unprivileged)
bir porttur; bu yüzden ne root yetkisine ne de bir capability'ye ihtiyaç
duyar. Portu dışarı açmanın iki yolu var.

### (a) seçeneği: yalnızca 2222 portunu aç (önerilen)

```bash
sudo ufw allow 2222/tcp comment 'ssh-honeypot'   # güvenlik duvarında gelen TCP 2222 bağlantılarına izin verir
```

Gerçek sshd'n olduğu yerde kalır. 2222'yi deneyen bot sayısı 22'yi
deneyenlerden azdır, ama yine de çoktur: yeni bir IP genellikle birkaç saat
içinde ilk denemeleri görür. Risk: düşük. Durdurmak için kuralı sil
(`sudo ufw delete allow 2222/tcp`, yani "2222 izin kuralını kaldır") veya
servisi durdur.

### (b) seçeneği: gerçek sshd'yi taşı ve 22 portunu yönlendir (ileri seviye)

> ⚠️ **KİLİTLENME UYARISI.** Bu, *senin* sunucuna nasıl bağlandığını
> değiştirir. Tek bir hata (portta bir yazım hatası, yanlış sırada bir
> güvenlik duvarı kuralı, aşağıdaki Ubuntu 24.04 socket activation
> ayrıntısı) ve web siteni ve mail'ini çalıştıran sunucuya SSH erişimini
> kaybedersin. Bunu yalnızca her satırı anlıyorsan, mevcut oturumunu baştan
> sona açık tutuyorsan ve sağlayıcının web/VNC konsolu elinin altındaysa
> yap. Linux'ta yeniysen **(a) seçeneğiyle kal.** **Kurulum scripti bunların
> hiçbirini bilerek otomatikleştirmez.**

Fikir şu: gerçek sshd başka bir porta taşınır (örneğin 22222) ve güvenlik
duvarı 22 numaralı porta gelen bağlantıları 2222'deki honeypot'a
yönlendirir. Ana hatlarıyla:

1. Mevcut SSH oturumunu açık tut. Can simidi olarak ikinci bir oturum aç.
2. **Önce** yeni porta izin ver:

   ```bash
   sudo ufw allow 22222/tcp               # yeni SSH portuna güvenlik duvarında izin verir
   ```

3. sshd'yi taşı. Ubuntu 24.04'te sshd "socket activation" ile çalışır ve
   dinlenecek port, bir systemd generator'ı aracılığıyla `sshd_config`
   dosyasından okunur:

   ```bash
   echo 'Port 22222' | sudo tee /etc/ssh/sshd_config.d/10-port.conf   # sshd için yeni portu bir ayar dosyasına yazar
   sudo sshd -t                           # sshd ayarlarının söz dizimini kontrol eder; hiçbir şey yazmamalı
   sudo systemctl daemon-reload           # systemd'nin ayarları (ve ssh socket'ini) yeniden okumasını sağlar
   sudo systemctl restart ssh.socket      # SSH socket'ini yeni portla yeniden başlatır (Debian 12'de: sudo systemctl restart ssh)
   ```

4. Dizüstü bilgisayarında **yeni** bir terminal aç ve dene:

   ```bash
   ssh -p 22222 sen@sunucun               # gerçek sunucuna yeni porttan bağlanmayı dener
   ```

   Bu çalışmadan devam etme. Dizüstündeki `~/.ssh/config` dosyasına bu
   sunucu için `Port 22222` satırını ekle; böylece gerçek parolanı 22
   portundaki honeypot'a yanlışlıkla yazmazsın (yazarsan diğer tüm denemeler
   gibi kaydedilir).

5. Yönlendirmeyi ekle. ufw kullanıyorsan aşağıdaki bloğu
   `/etc/ufw/before.rules` dosyasının en başına (`*filter` satırından önce)
   ekle; `eth0` yerine `ip -br link` komutunun gösterdiği ağ arayüzünün
   adını yaz:

   ```text
   *nat
   :PREROUTING ACCEPT [0:0]
   -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-ports 2222
   COMMIT
   ```

   ```bash
   sudo nano /etc/ufw/before.rules        # dosyayı nano metin düzenleyicisiyle açar (kaydet: Ctrl+O, çık: Ctrl+X)
   sudo ufw allow 2222/tcp                # yönlendirilen trafiğin ulaşacağı 2222 portuna izin verir
   sudo ufw reload                        # güvenlik duvarı kurallarını yeniden yükler
   ```

   IPv6 için aynı blok `/etc/ufw/before6.rules` dosyasına girer.

6. Dışarıdan kontrol et: `ssh root@sunucun` (22 portu) artık honeypot'u
   göstermeli (her parola başarısız olur) ve `ssh -p 22222 sen@sunucun` hâlâ
   gerçek sunucun olmalı.

Geri almak için, 22222'deki oturumun hâlâ açıkken: `*nat` bloğunu sil,
`sudo ufw reload` çalıştır, `10-port.conf` dosyasını sil, `daemon-reload`
yap ve `ssh.socket`'i yeniden başlat.

Docker kullanıyorsan yönlendirmeyi atlayıp `docker-compose.yml` içinde
`"2222:2222"` yerine `"22:2222"` yayınlayabilirsin; ama bunu da *sshd'yi
taşıdıktan sonra* yap. Kilitlenme uyarısı aynen geçerli.

---

## 2A. systemd ile kurulum (production sunucusunda önerilen)

Python 3.11+ gerekir (Ubuntu 24.04 ve Debian 12'de var).

```bash
sudo apt install python3-venv git              # sanal ortam (venv) desteğini ve git'i kurar
git clone https://github.com/rosko35/ssh-honeypot.git   # projeyi GitHub'dan indirir
cd ssh-honeypot                                # proje klasörüne girer
sudo ./deploy/install.sh                       # honeypot'u kurar ama başlatmaz
sudo nano /etc/ssh-honeypot/config.yml         # ayarları düzenler: politika, banner, sınırlar, saklama süresi
sudo nano /etc/ssh-honeypot/env                # isteğe bağlı Telegram ve dashboard bilgilerini düzenler
sudo systemctl enable --now ssh-honeypot       # servisi şimdi başlatır ve her açılışta otomatik başlamasını sağlar
journalctl -u ssh-honeypot -f                  # servisin loglarını canlı izler (çıkmak için Ctrl+C)
```

Logda `SSH honeypot listening on 0.0.0.0:2222` satırını görmelisin.

Script şunları yapar: `sshhoneypot` adında bir sistem kullanıcısı oluşturur
(shell'i, home dizini ve ek grubu yoktur); kodu ve bir sanal ortamı
(virtualenv) `/opt/ssh-honeypot` altına kurar (sahibi root'tur);
`/etc/ssh-honeypot/config.yml` ve `env` dosyalarını yalnızca yoksa oluşturur
(`0.0.0.0:2222` dinleyecek şekilde); iki systemd unit'i kurar ve
yapılandırmayı doğrular. Hiçbir paket kurmaz, başka hiçbir servise dokunmaz.
Host key'ler ilk açılışta `/var/lib/ssh-honeypot` içine üretilir (bunları
asla repoya kopyalama).

Unit'ler sıkı bir sandbox içinde çalışır. Güvenlik puanını görmek için:

```bash
systemd-analyze security ssh-honeypot          # servisin sandbox ayarlarını puanlar ve listeler
```

Önemli satırlar:

- `User=sshhoneypot`, `CapabilityBoundingSet=` (boş), `NoNewPrivileges=yes`
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `PrivateDevices=yes`; yazılabilir olan yalnızca `/var/lib/ssh-honeypot` ve
  `/var/log/ssh-honeypot`
- `/var/www`, `/etc/letsencrypt`, `/etc/ssl/private`, `/etc/nginx`, mail
  kutuları ve ayarları (`/var/mail`, `/etc/postfix`, `/etc/dovecot`, ...),
  veritabanı dizinleri ve `/etc/ssh` için `InaccessiblePaths=` (honeypot
  bunları göremez bile)
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SocketBindAllow=tcp:2222`
- `CPUQuota=25%`, `MemoryMax=256M`, `TasksMax=32`, `Nice=10`

**Portu değiştirmek:** `listen.port` değerini düzenle ve yeni portu bir
drop-in ile izinli yap:

```bash
sudo systemctl edit ssh-honeypot               # servis için bir ek ayar dosyası açar
#   açılan dosyaya şu iki satırı yaz:  [Service]  ve  SocketBindAllow=tcp:YENIPORT
sudo systemctl restart ssh-honeypot            # servisi yeni ayarlarla yeniden başlatır
```

Güncelleme (config, env, veritabanı ve host key'ler korunur):

```bash
git pull                                       # projenin en yeni sürümünü indirir
sudo ./deploy/install.sh                       # yeni kodu kurar
sudo systemctl restart ssh-honeypot            # servisi yeni kodla yeniden başlatır
```

Kaldırma: `sudo ./deploy/install.sh --uninstall` (config'i, veritabanını,
host key'leri, logları ve kullanıcıyı da silmek için `--purge` ekle).

## 2B. Docker ile kurulum

Compose v2.24 veya daha yenisi olan Docker Engine gerekir
(`docker compose version` sürümü gösterir).

```bash
git clone https://github.com/rosko35/ssh-honeypot.git ~/ssh-honeypot   # projeyi home dizinine indirir
cd ~/ssh-honeypot                           # proje klasörüne girer
cp .env.example .env && chmod 600 .env      # örnek gizli ayar dosyasını kopyalar ve yalnızca senin okuyabileceğin hale getirir
nano .env                                   # isteğe bağlı Telegram / dashboard bilgilerini düzenler
nano config.yml                             # politika, banner, sınırlar (dinleme adresini imaj ayarlar)
docker compose up -d --build                # imajı derler ve container'ı arka planda başlatır
docker compose logs -f                      # logları canlı izler; "SSH honeypot listening on 0.0.0.0:2222" satırını ara
docker compose --profile dashboard up -d    # isteğe bağlı: dashboard'u 127.0.0.1:8081 üzerinde başlatır
```

Container uid 10001 ile, tüm capability'ler düşürülmüş halde,
`no-new-privileges`, salt okunur kök dosya sistemi, küçük bir tmpfs ve CPU,
bellek, PID sınırlarıyla çalışır. Veritabanı, host key'ler ve `auth.log`
`honeypot-data` adlı volume'da durur.

> **Docker, ufw'yi atlar.** Yayınlanan (publish edilen) portlar kendi
> iptables kurallarını alır; bu yüzden `ufw status` listede göstermese bile
> `2222` dışarıdan erişilebilir olur. Burada istenen bu, ama aklında
> bulunsun - ve dashboard'u asla `127.0.0.1` dışında bir adreste yayınlama.

Güncelleme: `git pull && docker compose up -d --build` (yeni kodu indirir ve
container'ı yeniden derleyip başlatır). Her şeyi silmek için:
`docker compose down -v` (container'ları ve verileri içeren volume'u siler).

---

## 3. İsteğe bağlı: dışarıya bağlantıyı yasakla (egress filtresi)

Honeypot hiçbir zaman bir saldırgan adına bir yere bağlanmaz. Yapabileceği
tek dış bağlantı, isteğe bağlı Telegram bildirimidir. Telegram
kullanmıyorsan, servis kullanıcısı için "yeni dış bağlantı yok" kuralını
çekirdeğe uygulatabilirsin. Bu ek bir savunma katmanıdır: biri bir açık
bulup `sshhoneypot` olarak kod çalıştırsa bile, ikinci bir zararlı yazılım
indiremez veya senin IP'nden başka sunuculara saldıramaz.

systemd bunu tek başına ifade edemez (`IPAddressDeny=`, gelen ve giden
trafiği karşı tarafın adresine göre filtreler; gelen trafiğin ise herkese
açık kalması gerekir). ufw kullanan systemd kurulumunda,
`/etc/ufw/before.rules` (ve `before6.rules`) dosyasında, `*filter`
bölümünün içine, `-A ufw-before-output -o lo -j ACCEPT` satırından sonra şunu
ekle:

```text
-A ufw-before-output -m owner --uid-owner sshhoneypot -m conntrack --ctstate NEW -j REJECT
```

```bash
sudo nano /etc/ufw/before.rules             # kuralı eklemek için dosyayı açar
sudo ufw reload                             # güvenlik duvarını yeni kuralla yeniden yükler
```

Gelen bağlantılara verilen cevaplar `ESTABLISHED` durumundadır ve çalışmaya
devam eder; yeni dış bağlantılar (DNS dahil) reddedilir. Bu durumda Telegram
bildirimleri başarısız olur (uyarı olarak loglanır).

Docker için karşılığı, container'ın IP adresiyle eşleşen ve `DOCKER-USER`
zincirine eklenen bir kuraldır; kendi kurulumun için Docker belgelerine bak.

---

## 4. mini-siem'i bağla (isteğe bağlı)

[mini-siem](https://github.com/rosko35/mini-siem), honeypot'un `auth.log`
dosyasını mevcut `auth` parser'ıyla takip edebilir.

**İkisi de systemd ile kuruluysa:**

```bash
sudo usermod -aG sshhoneypot minisiem       # minisiem kullanıcısını sshhoneypot grubuna ekler (honeypot loglarını okuyabilsin diye)
sudo nano /etc/mini-siem/config.yml         # aşağıdaki kaynağı eklemek için mini-siem ayarlarını açar
sudo systemctl restart mini-siem            # mini-siem'i yeni ayar ve grup üyeliğiyle yeniden başlatır
```

```yaml
sources:
  - type: file
    path: /var/log/ssh-honeypot/auth.log
    parser: auth
```

Olaylar `honeypot` hostname'ini taşır. mini-siem'in SSH kuralları honeypot
trafiği için de alarm üretir (amaç da bu: kimin tarama yaptığına dair erken
uyarı). Alarmları yalnızca gerçek sshd için istiyorsan, o kurallara
`exclude: {host: honeypot}` ekle.

**Docker kurulumları:** honeypot'un auth logunu host'a yazmasını sağla;
böylece mini-siem'in container'ı (`/var/log`'u `adm` grubuyla salt okunur
bağlar) onu okuyabilir:

```bash
sudo install -d -o 10001 -g adm -m 2750 /var/log/ssh-honeypot   # sahibi container kullanıcısı, grubu adm olan bir log dizini oluşturur
```

Sonra `docker-compose.yml` içinde `honeypot:` altına
`- /var/log/ssh-honeypot:/logs` volume'unu ve
`HONEYPOT_AUTH_LOG: /logs/auth.log` ortam değişkenini ekle ve
`docker compose up -d` çalıştır.

---

## 5. Dashboard'u aç

Dashboard hiçbir zaman internete açık bir arayüzde dinlemez. Önce başlat:

```bash
sudo systemctl enable --now ssh-honeypot-dashboard   # dashboard servisini başlatır (Docker'da: --profile dashboard)
```

Sonra kendi bilgisayarından bir SSH tüneli aç:

```bash
ssh -N -L 8081:127.0.0.1:8081 sen@sunucun    # bilgisayarındaki 8081 portunu sunucudaki dashboard'a bağlar; (b) seçeneğinde -p 22222 ekle
```

ve tarayıcıda `http://localhost:8081` adresini aç. Tünel açık kaldığı sürece
dashboard çalışır; kapatmak için terminalde Ctrl+C.

systemd unit'i ayrıca makinenin kendisinden gelmeyen her paketi düşürür
(`IPAddressDeny=any`, `IPAddressAllow=localhost`).
`HONEYPOT_DASHBOARD_USER` / `HONEYPOT_DASHBOARD_PASSWORD` ikinci bir katman
olarak basic auth ekler.

---

## 6. Çalıştığını kontrol et

Başka bir makineden (asla gerçek bir parola yazma):

```bash
ssh -p 2222 -o PubkeyAuthentication=no root@sunucun   # honeypot'a bağlanır; uydurma bir parola yaz
```

Sonra sunucuda:

```bash
journalctl -u ssh-honeypot -n 20               # servisin son 20 log satırını gösterir
sudo tail -n 5 /var/log/ssh-honeypot/auth.log  # sshd tarzı logun son 5 satırını gösterir
sudo -u sshhoneypot HONEYPOT_CONFIG=/etc/ssh-honeypot/config.yml \
    /opt/ssh-honeypot/venv/bin/honeypot stats --days 1 --min-sources 1   # son 1 günün özetini Markdown olarak basar
```

## 7. Günlük işler

| Görev | systemd | Docker |
|---|---|---|
| Loglar | `journalctl -u ssh-honeypot -f` | `docker compose logs -f` |
| README istatistikleri | `sudo -u sshhoneypot HONEYPOT_CONFIG=/etc/ssh-honeypot/config.yml /opt/ssh-honeypot/venv/bin/honeypot stats --days 30` | `docker compose exec honeypot honeypot stats --days 30` |
| Saklama süresini hemen uygula | `... honeypot prune --days 30` | `docker compose exec honeypot honeypot prune --days 30` |
| Ayarları doğrula | `... honeypot check-config` | `docker compose exec honeypot honeypot check-config` |
| Ayar değişikliklerini uygula | `sudo systemctl restart ssh-honeypot` | `docker compose restart honeypot` |
| Disk kullanımı | `sudo du -sh /var/lib/ssh-honeypot /var/log/ssh-honeypot` | `docker system df -v` |

Saklama süresi (`retention_days`, varsayılan 90 gün) her saat otomatik
uygulanır. Metin logları 20 MB'ta döndürülür (3 eski dosya saklanır).

## 8. Gizlilik ve hukuk

README'deki "Hukuki notlar ve gizlilik" bölümünü oku. Kısaca: saldırgan
IP'leri ve yazılan kimlik bilgileri kişisel veridir; saldırganlar bazen
gerçek kimlik bilgileri yazar; veriyi yalnızca gerektiği kadar tut, erişimi
kısıtla, yakalanan kimlik bilgilerini hiçbir yerde kullanma ve kaydedilen
URL'leri bu sunucuda asla indirme.

## 9. Sorun giderme

- **Servis başlamıyor** - `journalctl -u ssh-honeypot -e` (logun sonunu
  gösterir) ile hataya bak. "Address already in use": 2222'yi başka bir şey
  dinliyor (`sudo ss -ltnp` ile kim olduğunu gör). Port açarken "Permission
  denied": ayarlanan port 2222 değil ve unit buna izin vermiyor ("Portu
  değiştirmek" bölümüne bak).
- **Hiç bağlantı gelmiyor** - 2222 portu engelli: `ufw status` ve
  sağlayıcının güvenlik duvarı panelini kontrol et; dışarıdan
  `nc -vz sunucun 2222` ile dene (port açıksa "succeeded" yazar).
- **Telegram sessiz** - varsayılan `reject` politikasında sahte shell'e hiç
  ulaşılmaz, yani bildirilecek bir şey yoktur; 3. adımdaki egress kuralı da
  Telegram'ı engeller. Hatalar token yazılmadan loglanır.
- **HASSH / cipher sütunları boş** - bir asyncssh güncellemesi iç alanları
  değiştirmiş; geri kalan her şey çalışır. `fingerprint.py` dosyasına bak.
- **Veritabanı hızlı büyüyor** - `retention_days` değerini düşür ve
  `honeypot prune` çalıştır; `max_connections_per_ip` ayarını da düşün.
