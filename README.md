# VeePN CLI (proxy-only)

دسکتاپ/لینوکسی معادل اپ اندروید VeePN: **همان سرورهای رایگان خود اپ** را
می‌گیرد (بدون نیاز به تعریف اشتراک)، همان `ss://` و `vmess://` را پارس می‌کند،
سرورها را ping می‌زند و یکی را پشت یک **پروکسی لوکال** (SOCKS5 + HTTP) اجرا
می‌کند. هیچ TUN/VPN ساخته نمی‌شود.

موتور پروتکل، کتابخانهٔ [sing-box](https://github.com/SagerNet/sing-box) است —
همان چیزی که اپ اندروید با `libbox` استفاده می‌کند، پس همان outboundها
(Shadowsocks، VMess با ws/http/grpc/quic/httpupgrade و TLS) و همان inbound
مختلط در دسترس‌اند.

## ساخت

```bash
cd veepn-cli
go build -o veepn .
./veepn help
```

## سرورهای رایگان (بدون اشتراک)

اپ اندروید لیست رایگانش را از یک اشتراک داخلی می‌گیرد که در سورس عمومی
`example.com` گذاشته شده؛ CLI همان endpointهای APK رسمی v2.5 را به‌عنوان
پیش‌فرض دارد، پس همین الان:

```bash
./veepn servers   # ۱۷۱ سرور در ۷۳ کشور
./veepn connect   # سریع‌ترین سرور رایگان + failover
```

رمز عبور هر سرور در آن لیست با AES-256-GCM رمز شده (کلید = SHA-256 یک رشتهٔ
ثابت، دقیقاً مثل `AlohaApi` در اپ) و CLI آن را قبل از ساخت کانفیگ باز می‌کند.
اگر endpointها روزی عوض شوند، کافی است لیست خودتان را تنظیم کنید:

```bash
veepn config set subscription_url "https://…/subscription"
veepn config set backup_url       "https://…/backup"
veepn config show
```

| کلید | پیش‌فرض | معنی |
|---|---|---|
| `subscription_url` | لیست رایگان اپ | اشتراک اصلی (لیست `ss://`)؛ خالی = رایگان |
| `backup_url` | بکاپ رایگان اپ | اشتراک پشتیبان (base64 از `vmess://`) |
| `socks_port` | `1080` | پورت inbound مختلط SOCKS5+HTTP (1-65535) |
| `http_port` | `8080` | پورت inbound HTTP (۰ = خاموش، برابر socks = همان inbound مختلط) |
| `ping_timeout_ms` | `3000` | تایم‌اوت هر probe |
| `cache_ttl_minutes` | `30` | عمر کش اشتراک |
| `log_level` | `warn` | سطح لاگ sing-box |
| `watchdog` | `true` | سلامت‌سنجی و اتصال مجدد خودکار |
| `http_proxy` | — | پروکسی برای *گرفتن خود اشتراک* (اختیاری؛ خالی = استفاده از `upstream`) |
| `upstream` | — | پروکسی زنجیره‌ای برای *رسیدن به سرورها*: `socks5://host:port` یا `http://host:port` |

متغیرهای محیطی: `VEEPN_SUB`، `VEEPN_SUB_BACKUP`، `VEEPN_HTTP_PROXY`،
`VEEPN_UPSTREAM`، `VEEPN_HOME`.

## اتصال از طریق یک پروکسی دیگر (upstream)

اگر سرورهای VeePN از شبکهٔ شما مستقیم در دسترس نیستند، می‌توانید با یک
پروکسی SOCKS5 یا HTTP موجود به آن‌ها برسید:

```bash
veepn connect --upstream socks5://127.0.0.1:1080
veepn connect --upstream http://user:pass@10.0.0.2:8080
veepn connect 3 --upstream 127.0.0.1:7890     # بدون scheme = SOCKS5
veepn ping  --upstream http://127.0.0.1:8080  # ping هم از همان مسیر رد می‌شود
veepn test  --upstream http://127.0.0.1:8080 --speed
veepn config set upstream socks5://127.0.0.1:1080   # دائمی
```

- سرور outbound در sing-box با `detour` پشت upstream زنجیره می‌شود؛ DNS و بقیهٔ
  ترافیک هم از همان مسیر می‌روند.
- `ping`/`test` هم از upstream عبور می‌کنند، پس انتخاب «سریع‌ترین» همان مسیری
  را می‌سنجد که `connect` استفاده می‌کند.
- دانلود خودِ subscription هم از همان upstream رد می‌شود، مگر اینکه
  `http_proxy` جداگانه ست شده باشد (آن اولویت دارد). این یعنی وقتی لیست
  سرورها هم فیلتر است، `veepn ping --upstream socks5://127.0.0.1:1080`
  بدون تنظیم اضافی کار می‌کند.
- `servers` هم فلگ `--upstream` را می‌پذیرد و فقط برای گرفتن subscription
  از آن استفاده می‌کند: `veepn servers --json --upstream socks5://127.0.0.1:1080`.
- `https://` برای upstream پشتیبانی نمی‌شود (فقط `socks5://` و `http://`).
- اعتبارنامه فقط در لاگ/وضعیت پنهان می‌شود؛ در `config.json` ذخیره می‌شود.

## تست واقعی و رتبه‌بندی

`ping` فقط TCP را چک می‌کند و برای سرورهایی که پورتشان باز است ولی تونل کار
نمی‌کند گمراه‌کننده است. `test` برای هر سرور یک **درخواست TLS واقعی از داخل
تونل** می‌فرستد (اول `generate_204`، اگر نشد `api.ipify.org`) و قابل استفاده
بودن را همان‌جا مشخص می‌کند:

```bash
./veepn test                     # همهٔ سرورهای رایگان، مرتب بر اساس تأخیر واقعی
./veepn test --speed --top 30    # + دانلود ۵۱۲KB برای هر سرور، مرتب بر اساس KB/s
./veepn test --json              # خروجی ماشین‌خوان
```

- `test` همیشه فقط **سرورهای رایگان** را می‌آزماید؛ `--configured` برای آزمودن
  اشتراک شخصی است.
- ستون `LAT` تأخیر واقعی تونل است (نه TCP)، `SPEED` سرعت دانلود، و وضعیت
  `✅ usable` / `🟡 slow` (بیش از ۸۰۰ms) / `❌` با دلیل خطاست.
- ستون `IDX` همان شمارهٔ سرور در لیست است، پس دقیقاً همان را به `connect` بدهید:
  `veepn connect 68`.
- کد خروجی ۰ اگر حداقل یک سرور سالم باشد، ۱ اگر هیچ‌کدام نباشند.

## دستورها

```bash
veepn servers [--refresh] [--json] [--upstream URL]   # لیست سرورها (کش ۳۰ دقیقه‌ای + کش آفلاین)
veepn test [--speed] [--json] [--top N]  # تست واقعی و رتبه‌بندی سرورهای رایگان
veepn ping [--json] [--timeout MS]   # فقط TCP ping (سریع ولی دقیق نیست)
veepn connect                       # سریع‌ترین سرور + failover خودکار
veepn connect --upstream socks5://127.0.0.1:1080   # اتصال از طریق پروکسی دیگر
veepn connect 3                     # سرور شمارهٔ ۳ از لیست
veepn connect 🇩🇪                    # یا بخشی از نام/پرچم/آی‌پی
veepn ports 1081 8081            # ذخیرهٔ پورت‌های پیش‌فرض (HTTP 0 = خاموش)
veepn connect --socks 1080 --http 8080   # فقط برای همین اجرا
veepn status [--json] [--check]
veepn ip                            # IP خروجی از طریق پروکسی
veepn ip --direct                   # IP واقعی (بدون پروکسی)
veepn log -n 100
veepn stop
```

بعد از `connect`:

```bash
export ALL_PROXY=socks5h://127.0.0.1:1080      # SOCKS5 (DNS هم از تونل)
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080     https://example.com
```

`connect` تا `Ctrl-C` در پیش‌زمینه می‌ماند و در همین مدت `status`, `ip`,
`stop` از ترمینال دیگری کار می‌کنند.

## معادل قابلیت‌های اپ اندروید

| اپ اندروید | این CLI |
|---|---|
| `SubscriptionApi` — اشتراک اصلی `ss://` + پشتیبان `vmess://` | `servers` (همان ترتیب: اول اصلی، در صورت خطا/خالی بودن پشتیبان) |
| پارس `ss://`/`vmess://`، حذف loopback، حذف نام‌های status/expiry، استخراج پرچم | همان قواعد در `internal/sub` |
| کش ۳۰ دقیقه‌ای حافظه + کش آفلاین (`lastFetchForCache`) | `cache.json` با همان قالب `{fetchedAt,kind,text}`؛ در صورت قطعی، لیست کش‌شده برمی‌گردد |
| Ping sweep موازی ۲۰ تایی + انتخاب Fastest با live-switch و skip سرورهای fail‌شده | `ping` و حالت پیش‌فرض `connect` (مرتب‌سازی بر اساس ms، تلاش پشت‌سرهم) |
| حالت پروکسی: `mixed` روی 1080 + `http` روی 8080 | همان دو inbound روی 127.0.0.1 |
| کانفیگ sing-box: DoH از طریق `proxy-out`، `ipv4_only`، `default_domain_resolver` | همان بخش‌های `dns`/`route` (بدون TUN و بدون ruleهای hijack-dns که فقط برای TUN لازم‌اند) |
| چک IP خروجی با `api.ipify.org` از طریق SOCKS | `connect` (بعد از اتصال) و `ip` |
| Watchdog: ۹۰ ثانیه بی‌حرکتی → optimize/reconnect | هر ۳۰ ثانیه `generate_204` از تونل؛ ۳ شکست → اتصال به سرور بعدی |
| ConnectLog / لاگ اتصال | `connect.log` در پوشهٔ تنظیمات + `log` |
| Last selection / cached servers / settings | `state.json`، `cache.json`، `config.json` |
| Crash log | خطاها روی stderr و در `connect.log` (اپ اندروید برای کرش WebView/Java داشت) |

قابلیت‌هایی که به‌طور طبیعی معنی ندارند و پیاده نشده‌اند: TUN/VPN و
split-tunnel بر اساس پکیج، تم/آیکون اپ‌ها، QR و WebView UI.

## تست

```bash
cd veepn-cli
go test ./...
```

تست `internal/engine` یک سرور Shadowsocks محلی با sing-box بالا می‌آورد، کانفیگ
این CLI را به آن وصل می‌کند و یک صفحهٔ HTTP محلی را هم از SOCKS و هم از HTTP
inbound می‌خواند (مسیر کامل inbound → outbound بدون نیاز به سرور واقعی).

## نکته‌های امنیتی

- رمز/`uuid` فقط در حافظه و در `cache.json` با مجوز `0600` ذخیره می‌شود؛
  در جدول‌ها و `connect.log` هرگز چاپ نمی‌شود (فقط `proto`، پرچم و `ip:port`).
- `config.json` و `state.json` با `0600` نوشته می‌شوند (آدرس اشتراک می‌تواند توکن داشته باشد).
