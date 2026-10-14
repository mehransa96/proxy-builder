# Proxy Builder

یک وب‌اپلیکیشن قدرتمند و مستقل با پنج ابزار:

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>🧪 Templates</b> (تب پیش‌فرض) — بازسازی کانفیگ بر اساس دو الگوی برگرفته از کانفیگ‌هایی که روی همراه اول وصل می‌شوند.</li>
  <li><b>🩺 Config Fixer</b> — عیب‌یابی و اصلاح کانفیگ کامل JSON برای v2rayNG معمولی (فینگرپرینت، فرگمنت کلاسیک، حلقه‌ی DNS، بسته‌ی تست).</li>
  <li><b>🛡️ ECH</b> — ارتقای لینک <b>VLESS</b> یا <b>Trojan</b> با افزودن پارامترهای <code>fp</code> (اثر انگشت TLS، پیش‌فرض <code>chrome</code>) و <code>ech</code> (ECH Config List) به‌همراه قابلیت تغییر سرور (IP/دامنه) — خروجی لینکی آماده برای وارد کردن در کلاینت خودتان.</li>
  <li><b>🧬 Fragment + Fingerprint</b> — ارتقای لینک <b>VLESS</b> یا <b>Trojan</b> با افزودن پارامترهای <code>cs</code> (لیست Cipher Suites)، <code>fm</code> (Fragment Mask) و <code>fp</code> (اثر انگشت TLS) به‌همراه قابلیت تغییر سرور (IP/دامنه) — خروجی لینکی آماده برای وارد کردن در کلاینت خودتان. ساب‌تب <b>📥 Subscription</b> آن لینک اشتراک را می‌گیرد (یا محتوایش را) و همه کانفیگ‌های <b>VLESS</b> و <b>Trojan</b> داخل آن را دسته‌جمعی ارتقا می‌دهد، با خروجی کپی، <code>.txt</code> و <code>base64</code>.</li>
  <li><b>🔗 Chain Builder</b> — ترکیب دو کانفیگ پراکسی به یک کانفیگ واحد <b>Xray</b> یا <b>Sing-box</b> برای افزایش پایداری اتصال و استفاده از آی‌پی ثابت.</li>
</ul>

تمام پردازش‌ها درون مرورگر شما انجام می‌شود. هیچ داده‌ای به سروری ارسال نمی‌گردد. دریافت لینک اشتراک فقط با همان آدرسی که وارد کرده‌اید ارتباط برقرار می‌کند؛ محتوای جای‌گذاری یا رها‌شده هرگز از مرورگر شما خارج نمی‌شود.

## 🚀 ویژگی‌ها

### 🧪 Templates (تب پیش‌فرض)
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>تحلیل</b>: کانفیگ کامل JSON (یا لینک) را جای‌گذاری کنید تا تب نشان دهد چه کاری می‌کند — ترنسپورت، SNI، فینگرپرینت، REALITY، domain fronting، finalmask، پین DNS، DNS داخلی و balancer.</li>
  <li><b>قالب A — اتصال مستقیم + پین DNS</b> (برگرفته از یک کانفیگ سالم VLESS + REALITY): سرور شما را نگه می‌دارد و بقیه را می‌سازد: فینگرپرینت chrome، فرگمنت finalmask با <code>1-3 · 50-100 · 10-20 · maxSplit 10</code> به‌همراه نویز UDP (Xray-core نسخه ۲۶ به بعد)، <code>UseIP</code> با happy-eyeballs، پین کردن دامنه‌ی سرور به IP آن در <code>dns.hosts</code> (دکمه‌ی <b>Look up</b> آن را با DNS-over-HTTPS پیدا می‌کند) یا resolve با DNS داخلی مستقیم، و مستقیم‌کردن همه‌ی DNSهای داخلی.</li>
  <li><b>قالب B — چند آدرس CDN با balancer</b> (برگرفته از یک کانفیگ سالم VLESS + ws + TLS پشت CDN): برای هر آدرسی که وارد کنید (لبه‌ی CDN، IP تمیز، دامنه‌ی دیگر) یک عضو balancer، فینگرپرینت‌های chrome / edge، <code>leastLoad</code> + <code>burstObservatory</code>، یک عضو fallback، DNS ایرانی (شکن / بگذر) برای دامنه‌های .ir و بدون DNS هسته برای آدرس سرور. تغییر اختیاری SNI / Host / ALPN برای domain fronting.</li>
</ul>

### 🩺 Config Fixer
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>عیب‌یابی</b>: کانفیگ کامل JSON (خروجی <b>Export full configuration</b> در v2rayNG یا Custom) یا لینک <code>vless://</code> / <code>vmess://</code> / <code>trojan://</code> را جای‌گذاری کنید. تب مشکلات را فهرست می‌کند: فینگرپرینت <code>unsafe</code> (TLS خود Go، فقط برای PattNG)، <code>finalmask</code> (فقط Xray-core نسخه ۲۶ به بعد — هسته‌های قدیمی‌تر بی‌صدا نادیده‌اش می‌گیرند)، نبودِ فرگمنت TLS، ws/httpupgrade با ALPN <code>h2</code>، آدرس IP بدون SNI، <code>allowInsecure</code>، <code>dialerProxy</code> به outbound ناموجود، mux همراه با flow، و حلقه‌ی DNS (دامنه‌ی سرور با DNSی resolve می‌شود که ترافیکش از خود پراکسی می‌گذرد).</li>
  <li><b>اصلاح</b>: فینگرپرینت مرورگر (پیش‌فرض <code>chrome</code>) می‌گذارد، <b>فرگمنت کلاسیک</b> را اضافه می‌کند — یک outbound از نوع <code>freedom</code> با تگ <code>fragment</code> و مقادیر <code>packets / length / interval</code> که با <code>sockopt.dialerProxy</code> وصل می‌شود (روی همه‌ی هسته‌های Xray کار می‌کند) — <code>finalmask</code> و <code>cipherSuites</code> بی‌اثر را حذف می‌کند، ALPN را برای ws روی <code>http/1.1</code> می‌گذارد، برای دامنه‌ی سرور یک قانون DNS مستقیم اضافه می‌کند و می‌تواند آدرس را با IP تمیز عوض کند و SNI / Host را نگه دارد. بقیه‌ی کانفیگ دست‌نخورده می‌ماند. حالت Final Mask برای PattNG هنوز در دسترس است.</li>
  <li><b>بسته‌ی تست (Test Pack)</b>: یک آرایه‌ی JSON می‌سازد با یک کانفیگ برای هر پریست فرگمنت به‌اضافه‌ی یک نسخه‌ی بدون فرگمنت، هرکدام با نام جدا. همه را وارد کنید، تست real-delay بگیرید و هرکدام که وصل شد را نگه دارید — هیچ مقدار فرگمنتی روی همه‌ی شبکه‌ها کار نمی‌کند.</li>
</ul>

### 🛡️ ECH
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>جای‌گذاری و ارتقا</b>: لینک تکی یا چندگانه (تک‌به‌تک در هر خط) از <code>vless://</code> یا <code>trojan://</code> را جای‌گذاری کنید و لینک‌های ارتقایافته با پارامترهای <code>fp</code> و <code>ech</code> دریافت کنید.</li>
  <li><b>ورودی اشتراک</b>: لینک اشتراک را برای دانلود در مرورگر جای‌گذاری کنید — یا محتوای آن را (متن ساده یا base64) جای‌گذاری کنید — تا همه کانفیگ‌های VLESS و Trojan داخل آن با همان گزینه‌های ECH ارتقا یابند. تغییر سرور در اینجا نادیده گرفته می‌شود (هر کانفیگ آدرس خودش را نگه می‌دارد)؛ با تغییر گزینه‌های ECH، کانفیگ‌های گرفته‌شده بدون دانلود مجدد ارتقا می‌یابند.</li>
  <li><b>تغییر سرور</b>: فیلد سرور (IP/دامنه) فقط برای کانفیگ تکی به‌صورت خودکار از URL استخراج می‌شود و قابل ویرایش است. در حالت چند کانفیگ، این فیلد خالی می‌ماند و فقط اگر مقدار دلخواه وارد کنید روی همه کانفیگ‌ها اعمال می‌شود (پشتیبانی از IPv4، IPv6 و دامنه).</li>
  <li><b>اثر انگشت (Fingerprint)</b>: پیش‌فرض <code>chrome</code> با گزینه‌های <code>unsafe</code>، <code>firefox</code>، <code>safari</code>، <code>random</code> و <code>none</code>.</li>
  <li><b>پریست‌های ECH</b>: سلکتور <code>ECH Server</code> از ابتدا با مقدار پیشنهادی <code>cloudflare-ech.com + udp://1.1.1.1</code> پر شده است و ۱۸ پریست cloudflare-ech.com روی ریزالورهای UDP عمومی ارائه می‌دهد. فیلد همچنان دستی قابل ویرایش است.</li>
  <li><b>دامنه خالی</b>: نوشتن فقط دامنه (مثل <code>cloudflare-ech.com</code>) به‌صورت خودکار <code>+udp://8.8.8.8</code> اضافه می‌کند؛ مقدار base64 دست‌نخورده عبور می‌کند.</li>
  <li><b>آگاه از TLS</b>: پارامتر <code>ech</code> فقط زمانی اضافه می‌شود که کانفیگ از امنیت <code>tls</code> استفاده کند. با خالی کردن فیلد، آن پارامتر حذف می‌شود.</li>
  <li><b>کپی با یک کلیک</b>: کپی مستقیم لینک ارتقایافته در کلیپ‌بورد.</li>
  <li><b>خروجی</b>: دانلود <code>.txt</code> (هر خط یک کانفیگ) یا <code>base64 .txt</code> (فرمت استاندارد بدنه اشتراک).</li>
  <li><b>پشتیبانی از پروتکل‌ها</b>: <b>VLESS</b> و <b>Trojan</b>.</li>
</ul>

### 🧬 Fragment + Fingerprint
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>جای‌گذاری و ارتقا</b>: لینک تکی یا چندگانه (تک‌به‌تک در هر خط) از <code>vless://</code> یا <code>trojan://</code> را جای‌گذاری کنید و لینک‌های ارتقایافته با پارامترهای <code>cs</code>، <code>fm</code> و <code>fp</code> دریافت کنید.</li>
  <li><b>کانفیگ کامل JSON</b>: به‌جای لینک، کل کانفیگ JSON ایکس‌ری را جای‌گذاری کنید — مثلاً خروجی <b>Export full configuration</b> در v2rayNG / PattNG یا یک کانفیگ <b>Custom</b>. تب به‌صورت خودکار آن را تشخیص می‌دهد (ورودی‌ای که با <code>{</code> یا <code>[</code> شروع شود)، روی هر outbound از نوع VLESS / VMess / Trojan مقدار <code>fp</code> را در <code>tlsSettings.fingerprint</code> (یا <code>realitySettings.fingerprint</code>)، <code>cs</code> را در <code>tlsSettings.cipherSuites</code> و <code>fm</code> را در <code>streamSettings.finalmask</code> می‌نویسد و JSON کامل را برمی‌گرداند؛ بقیه بخش‌ها (<code>dns</code>، <code>routing</code>، <code>inbounds</code>، <code>policy</code>، <code>remarks</code>، outboundهای دیگر و <code>sockopt</code> موجود) دست‌نخورده می‌مانند. تغییر سرور فقط وقتی اعمال می‌شود که کانفیگ یک outbound پراکسی داشته باشد. دانلود، فایل <code>enhanced-config.json</code> می‌سازد.</li>
  <li><b>پشتیبانی از چندین کانفیگ همزمان</b>: امکان جای‌گذاری لیست انبوه کانفیگ‌ها جهت پردازش، اعتبارسنجی و ارتقای دسته‌جمعی بدون تداخل در remark کانفیگ‌ها.</li>
  <li><b>تغییر سرور</b>: فیلد سرور (IP/دامنه) فقط برای کانفیگ تکی به‌صورت خودکار از URL استخراج می‌شود و قابل ویرایش است. در حالت چند کانفیگ، این فیلد خالی می‌ماند و فقط اگر مقدار دلخواه وارد کنید روی همه کانفیگ‌ها اعمال می‌شود (پشتیبانی از IPv4، IPv6 و دامنه).</li>
  <li><b>اثر انگشت (Fingerprint)</b>: پیش‌فرض <code>unsafe</code> با گزینه‌های <code>chrome</code>، <code>firefox</code>، <code>safari</code>، <code>random</code> و <code>none</code>.</li>
  <li><b>نسخه‌های فرگمنت (Fragment)</b>: فیلد <code>fm</code> دارای دو preset است — <code>v1</code> کلاسیک (<code>5,94,1</code> / <code>109,1</code> / split برابر <code>355</code>) و <code>v2</code> جدید (پیش‌فرض: <code>0,104,1</code> / <code>114,1</code> / split برابر <code>11</code>). با سلکتور <code>Fragment Version</code> جابه‌جا شوید؛ فیلد همچنان دستی قابل ویرایش است.</li>
  <li><b>آگاه از TLS</b>: پارامترهای <code>cs</code> و <code>fm</code> فقط زمانی اضافه می‌شوند که کانفیگ از امنیت <code>tls</code> استفاده کند. با خالی کردن هر فیلد، آن پارامتر حذف می‌شود.</li>
  <li><b>ساب‌تب اشتراک</b>: لینک اشتراک را مستقیم در مرورگر دریافت کنید، رمزگشایی (متن ساده یا base64) و ارتقای دسته‌جمعی کانفیگ‌های VLESS و Trojan داخل آن — یا محتوایش را جای‌گذاری کنید / فایل <code>.txt</code> ذخیره‌شده را روی کارت بیندازید تا دانلود لازم نباشد. از همان گزینه‌های <code>fp</code> / <code>cs</code> / <code>fm</code> بالا استفاده می‌شود؛ تغییر سرور نادیده گرفته می‌شود (هر کانفیگ آدرس خودش را نگه می‌دارد).</li>
  <li><b>providerهای بسته</b>: اگر provider هدر CORS نفرستد، خطا ۳ قدم راهنمایی به‌همراه دکمه <b>Open link</b> برای باز کردن لینک در تب جدید و کپی نشان می‌دهد.</li>
  <li><b>خروجی</b>: کپی در کلیپ‌بورد، دانلود <code>.txt</code> (هر خط یک کانفیگ) یا <code>base64 .txt</code> (فرمت استاندارد بدنه اشتراک).</li>
  <li><b>بدون ECH</b>: پارامتر <code>ech</code> فقط در تب <b>ECH</b> اعمال می‌شود — به کانفیگ‌های اشتراک اضافه نمی‌گردد.</li>
  <li><b>پشتیبانی از پروتکل‌ها</b>: فقط <b>VLESS</b> و <b>Trojan</b> ارتقا می‌یابند؛ بقیه پروتکل‌های داخل ساب شمرده‌شده و رد می‌شوند.</li>
</ul>

### 🔗 Chain Builder
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>ترکیب دوگانه کانفیگ</b>: به‌راحتی یک پراکسی اولیه (مانند Worker/CDN) را با یک پراکسی زنجیره‌ای (Chain Proxy) ترکیب کنید.</li>
  <li><b>پشتیبانی از پروتکل‌ها</b>: پشتیبانی از <b>VLESS</b>، <b>VMess</b>، <b>Trojan</b>، <b>Shadowsocks</b>، <b>SOCKS</b>، <b>HTTP</b> و <b>SSH</b>.</li>
  <li><b>خروجی دوگانه</b>: تولید کانفیگ JSON برای هر دو کلاینت <b>Xray</b> و <b>Sing-box</b>.</li>
  <li><b>پشتیبانی از ECH</b>: استخراج و افزودن خودکار تنظیمات ECH برای اتصالی امن‌تر.</li>
</ul>

## 📦 فرمت‌های خروجی

<table dir="rtl" width="100%" style="direction: rtl; text-align: right;">
  <thead>
    <tr>
      <th align="right">خروجی</th>
      <th align="right">کلاینت</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Xray JSON</b></td>
      <td>قابل استفاده در تمام کلاینت‌های سازگار با Xray&rlm; (مانند v2rayN&rlm;، v2rayNG&rlm;، Nekoray&rlm; و غیره).</td>
    </tr>
    <tr>
      <td><b>Sing-box JSON</b></td>
      <td>دارای زیر-تب‌های تخصصی برای کلاینت‌های مختلف (بخش پایین را ببینید).</td>
    </tr>
  </tbody>
</table>

### 📦 فرمت‌های تخصصی Sing-box
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>Standard</b>: کانفیگ استاندارد هسته Sing-box.</li>
  <li><b>Nekoray</b>: بهینه‌سازی شده برای حداکثر سازگاری با <b>Nekoray</b>.</li>
  <li><b>Nekobox (Android)</b>: مخصوص اندروید؛ دارای <b>رابط مجازی TUN</b> برای شناسایی صحیح VPN در سیستم‌عامل (نمایش آیکون کلید) و پایداری بیشتر در شبکه موبایل.</li>
</ul>

## 🔗 شیوه کار Chain Builder

این ابزار کانفیگی تولید می‌کند که ترافیک شما را به این ترتیب مسیریابی می‌کند:

<p dir="rtl" align="center" style="direction: rtl;">
  <code>شما ⬅️ کانفیگ ۱ (پراکسی اولیه) ⬅️ کانفیگ ۲ (Chain) ⬅️ اینترنت</code>
</p>

این ساختار تضمین می‌کند که آی‌پی خروجی و نهایی شما همان آی‌پی <b>کانفیگ ۲ (Chain Proxy&rlm;)</b> باشد، که هویتی ثابت و پایدار برای وب‌سایت‌هایی که از آنها بازدید می‌کنید، فراهم می‌آورد.

## 🛠️ نحوه استفاده

برای پشتیبانی کامل از کلیپ‌بورد، این پوشه را به‌صورت محلی سرو کنید — مثلاً `python3 -m http.server` یا `npx serve` — سپس از طریق `http://localhost:PORT` (یا HTTPS) باز کنید؛ باز کردن مستقیم فایل (`file://`) به کپی دستی برمی‌گردد.

### 🧪 Templates
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li>برنامه را باز کنید — تب <b>Templates</b> به‌صورت پیش‌فرض فعال است.</li>
  <li>کانفیگ کامل JSON (یا لینک) را جای‌گذاری کنید و تحلیل را بخوانید.</li>
  <li><b>A</b> را انتخاب کنید (REALITY یا یک سرور TLS؛ با <b>Look up</b> آی‌پی سرور را پین کنید) یا <b>B</b> (TLS پشت CDN؛ چند آدرس وارد کنید).</li>
  <li>روی <b>Build from Template</b> بزنید، کپی کنید و در v2rayNG از <b>+ ← Import config from clipboard</b> وارد کنید.</li>
</ol>

### 🩺 Config Fixer
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li>برنامه را باز کنید و به تب <b>Config Fixer</b> بروید.</li>
  <li>کانفیگ کامل JSON (یا لینک) را جای‌گذاری کنید و نتیجه‌ی عیب‌یابی را بخوانید.</li>
  <li>با تنظیمات پیش‌فرض (chrome، فرگمنت کلاسیک، DNS مستقیم) روی <b>Fix Config</b> بزنید — یا <b>Build Test Pack</b> برای چند نسخه‌ی مختلف.</li>
  <li>خروجی را کپی کنید و در v2rayNG از <b>+ ← Import config from clipboard</b> وارد کنید (یا فایل <code>.json</code> را دانلود کنید).</li>
</ol>

### 🛡️ ECH
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li>برنامه را باز کنید و به تب <b>ECH</b> بروید.</li>
  <li>لینک <b>VLESS</b> یا <b>Trojan</b> خود را جای‌گذاری کنید.</li>
  <li>در صورت نیاز گزینه‌ها را تنظیم کنید: تغییر سرور (به‌صورت خودکار از URL پر می‌شود)، اثر انگشت (پیش‌فرض <code>chrome</code>)، پریست سرور ECH یا مقدار دستی (دامنه خالی به‌صورت خودکار <code>+udp://8.8.8.8</code> اضافه می‌کند).</li>
  <li>روی <b>«Enhance URL»</b> کلیک کنید و لینک حاصل را کپی کرده و در کلاینت خود وارد کنید (هسته Xray، سینگ‌باکس ۱.۱۳ به بعد یا Clash نسخه ۱.۱۹.۲۰ به بعد).</li>
  <li>برای کانفیگ‌های انبوه، از کارت <b>ورودی اشتراک</b> استفاده کنید: لینک را جای‌گذاری کرده و <b>«Fetch & Enhance Sub»</b> را بزنید — یا محتوای اشتراک را مستقیم جای‌گذاری کنید.</li>
</ol>

### 🧬 Fragment + Fingerprint
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li>به تب <b>Fragment + Fingerprint</b> بروید.</li>
  <li>لینک <b>VLESS</b> یا <b>Trojan</b> خود را جای‌گذاری کنید.</li>
  <li>در صورت نیاز گزینه‌ها را تنظیم کنید: تغییر سرور (به‌صورت خودکار از URL پر می‌شود)، اثر انگشت، لیست Cipher Suites و Final Mask.</li>
  <li>روی <b>«Enhance URL»</b> کلیک کنید و لینک حاصل را کپی کرده و در کلاینت خود وارد کنید.<br><b>کانفیگ کامل JSON</b>: به‌جای لینک، کل JSON خروجی‌گرفته‌شده را در همین کادر جای‌گذاری کنید؛ دکمه به <b>«Enhance JSON»</b> تغییر می‌کند. نتیجه را کپی کنید (یا <code>enhanced-config.json</code> را دانلود کنید) و در کلاینت به‌عنوان <b>Custom config</b> (از کلیپ‌بورد یا فایل) وارد کنید.</li>
  <li>برای کانفیگ‌های انبوه، به ساب‌تب <b>📥 Subscription</b> بروید: لینک اشتراک را جای‌گذاری کنید و <b>«Fetch & Enhance»</b> را بزنید — یا محتوای آن را جای‌گذاری کنید (یا فایل <code>.txt</code> را روی کارت بیندازید) تا دانلود لازم نباشد. اگر دانلود بسته بود، ۳ قدم نمایش‌داده‌شده را دنبال کنید (باز کردن لینک با <b>Open link</b>، کپی، جای‌گذاری و Fetch مجدد). کانفیگ‌های ارتقایافته را کپی یا دانلود کنید (<code>.txt</code> یا <code>base64 .txt</code>).</li>
</ol>

#### ✅ الزامات کلاینت
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>ویندوز</b>: حتماً از نرم‌افزار <a href="https://github.com/patterniha/PattN">PattN</a> استفاده کنید.</li>
  <li><b>اندروید</b>: حتماً از نرم‌افزار <a href="https://github.com/patterniha/PattNG">PattNG</a> استفاده کنید.</li>
</ul>

### 🔗 Chain Builder
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>کانفیگ ۱</b>: لینک پراکسی اول خود را جای‌گذاری کنید (این کانفیگ می‌تواند یک Cloudflare Worker&rlm;، CDN&rlm; یا هر پراکسی مشابهی باشد).</li>
  <li><b>کانفیگ ۲</b>: لینک پراکسی دوم که می‌خواهید ترافیک از آن عبور کند، جای‌گذاری نمایید.
    <ul>
      <li>برای <b>SSH</b>، روی دکمه 🔑 SSH کلیک کنید و مشخصات سرور، پورت، نام کاربری و رمز عبور را وارد نمایید.</li>
    </ul>
  </li>
  <li><b>تنظیمات</b>: در صورت نیاز، سرور DNS&rlm; یا پورت SOCKS&rlm; را تغییر دهید.</li>
  <li><b>تولید خروجی</b>: روی "Generate Chained Config" (تولید کانفیگ زنجیره‌ای) کلیک کنید تا JSON&rlm; شما آماده شود.</li>
  <li><b>استفاده در کلاینت</b>: کد JSON&rlm; را کپی کرده یا به‌صورت فایل دانلود کنید و در کلاینت دلخواه خود استفاده نمایید.</li>
</ol>

## 📋 پروتکل‌های پشتیبانی‌شده

<table dir="rtl" width="100%" style="direction: rtl; text-align: right;">
  <thead>
    <tr>
      <th align="right">پروتکل</th>
      <th align="right">فرمت لینک</th>
      <th align="right">توضیحات</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>VLESS</b></td>
      <td dir="ltr" align="left"><code>vless://uuid@server:port?params</code></td>
      <td>پشتیبانی در هر سه ابزار</td>
    </tr>
    <tr>
      <td><b>VMess</b></td>
      <td dir="ltr" align="left"><code>vmess://base64-json</code></td>
      <td>فقط Chain Builder</td>
    </tr>
    <tr>
      <td><b>Trojan</b></td>
      <td dir="ltr" align="left"><code>trojan://password@server:port?params</code></td>
      <td>پشتیبانی در هر سه ابزار</td>
    </tr>
    <tr>
      <td><b>Shadowsocks</b></td>
      <td dir="ltr" align="left"><code>ss://base64(method:pass)@server:port</code></td>
      <td>فقط Chain Builder — عدم پشتیبانی از transport&rlm; (مانند ws&rlm;، grpc&rlm; و غیره) و همچنین فاقد پشتیبانی از TLS&rlm;.</td>
    </tr>
    <tr>
      <td><b>SOCKS</b></td>
      <td dir="ltr" align="left"><code>socks://user:pass@server:port</code></td>
      <td>فقط Chain Builder — باید شامل نام کاربری و رمز عبور باشد.</td>
    </tr>
    <tr>
      <td><b>HTTP</b></td>
      <td dir="ltr" align="left"><code>http://user:pass@server:port</code></td>
      <td>فقط Chain Builder — باید شامل نام کاربری و رمز عبور باشد.</td>
    </tr>
    <tr>
      <td><b>SSH</b></td>
      <td>دارای ۴ فیلد (سرور، پورت، نام کاربری، رمز عبور)</td>
      <td>فقط Chain Builder — <b>فقط برای Sing-box&rlm;</b> — توسط Xray&rlm; پشتیبانی نمی‌شود.</td>
    </tr>
  </tbody>
</table>

## ⚠️ نکات مهم

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li>ابزار <b>Fragment + Fingerprint</b> فقط از لینک‌های <b>VLESS</b> و <b>Trojan</b> پشتیبانی می‌کند.</li>
  <li><b>TLS الزامی است</b>: ابزار <b>Fragment + Fingerprint</b> فقط با کانفیگ‌هایی کار می‌کند که <b>TLS</b> فعال داشته باشند (امنیت <code>tls</code> یا <code>reality</code>). کانفیگ‌های غیر TLS پشتیبانی نمی‌شوند و کار نخواهند کرد.</li>
  <li>پارامترهای <b>cs</b> (Cipher Suites) و <b>fm</b> (Final Mask) فقط زمانی اضافه می‌شوند که کانفیگ از امنیت <b>tls</b> استفاده کند.</li>
  <li>کانفیگ‌های <b>SOCKS</b> و <b>HTTP</b> باید حتماً دارای <b>نام کاربری و رمز عبور</b> باشند.</li>
  <li>هسته <b>Xray</b> از کانفیگ‌های <b>raw</b> (بدون هدر TCP&rlm;) پشتیبانی نمی‌کند؛ به‌جای آن باید از TCP&rlm; با هدر http&rlm; استفاده کرد.</li>
  <li>کانفیگ‌های <b>Shadowsocks</b> نمی‌توانند هیچ نوع transport&rlm; (مانند WebSocket&rlm;، gRPC&rlm;، HTTPUpgrade&rlm; و غیره) داشته باشند و فاقد قابلیت TLS&rlm; هستند.</li>
  <li>پروتکل <b>SSH</b> تنها توسط <b>Sing-box</b> پشتیبانی می‌شود. زمانی که از SSH&rlm; استفاده می‌کنید، تب مربوط به Xray&rlm; به‌صورت خودکار غیرفعال خواهد شد. برای استفاده از آن، لطفاً کلاینت <a href="https://sing-box.sagernet.org/">sing-box&rlm;</a> را به کار ببرید.</li>
</ul>

## 🔧 انتقال‌های (Transports) پشتیبانی‌شده

TCP، TCP (http header)، WebSocket، gRPC، HTTPUpgrade، XHTTP&rlm; (لینک‌های <code>splithttp</code>&rlm; هم پذیرفته می‌شوند)

در خروجی Xray&rlm;، مقادیر <code>host</code>&rlm;، <code>path</code>&rlm;، <code>mode</code>&rlm; و <code>extra</code>&rlm; لینک XHTTP&rlm; حفظ می‌شوند. خروجی Sing-box&rlm; از transport&rlm; با نوع <code>xhttp</code>&rlm; استفاده می‌کند که فقط نسخه‌هایی از Sing-box&rlm; که XHTTP&rlm; را اضافه کرده‌اند آن را می‌شناسند؛ نسخه‌ی اصلی Sing-box&rlm; به‌جای اتصال بی‌صدا از طریق TCP&rlm; ساده، آن را رد می‌کند.

## 🔒 پروتکل‌های رمزنگاری (TLS) پشتیبانی‌شده

TLS، Reality، None

## 📦 تکنولوژی‌های استفاده‌شده

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>HTML5</b>: ساختار معنایی.</li>
  <li><b>CSS3</b>: متغیرهای سفارشی، افکت‌های شیشه‌ای (Glassmorphism) و انیمیشن‌ها.</li>
  <li><b>JavaScript</b>: منطق اصلی برای پارس لینک، ارتقای کانفیگ و تولید JSON.</li>
  <li><b>فونت‌ها</b>: فونت‌های Inter و JetBrains Mono به‌صورت محلی (پوشه <code>fonts/</code> با فرمت woff2) میزبانی می‌شوند — هیچ درخواستی به CDN فونت ارسال نمی‌گردد.</li>
</ul>

## 🛡️ کردیت‌ها (Credits)

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li>منطق ارتقای <b>Fragment + Fingerprint</b> (افزودن پارامترهای <code>cs</code> / <code>fm</code> / <code>fp</code> و فرمت خروجی لینک) بر اساس رفتار «Export to Clipboard» پروژه‌ی <a href="https://github.com/patterniha/PattNG">PattNG</a> طراحی شده است.</li>
  <li>ابزار <b>Chain Builder</b> از منطق و ساختار پروژه متن‌باز <a href="https://github.com/bia-pain-bache/BPB-Worker-Panel">BPB-Worker-Panel</a> و این <a href="https://gist.github.com/alireza-delavari/62e56af0d59c92b5b1798f1442f90f61">تنظیمات Sing-box</a> ایده گرفته است.</li>
</ul>

## 📚 لاگ تصمیم‌ها

تصمیم‌های قطعی در `plans/README.md` ثبت می‌شود (ملاک همان است — اگر این خلاصه قدیمی شد، لاگ معتبر است؛ اگر لاگ بزرگ‌تر شد، فقط به اشاره بسنده می‌کنیم):
- رفتار بالک VMess رفتار مستند است، نه کمبود.
- پریست‌های ECH قابل‌ویرایش رد شد — فیلد دستی مقادیر سفارشی را پوشش می‌دهد.
- تفکیک گادفایل به تعویق افتاد تا پوشش pure کامل شود (011/016/017 در بازبینی انجام شد).
- پاس‌ترو `domain+resolver` برای ech در Xray طبق مستندات Xray درست است (C-11 رد شد).
- موارد سبز کم‌اهمیت (packet_encoding، نگاشت لاگ، قانون remote-dns، link rel، ماسک اعتبار) خارج از scope اپراتور است، نه رد بر اساس شایستگی.

---
توسعه‌یافته با ❤️ برای حریم خصوصی شما.