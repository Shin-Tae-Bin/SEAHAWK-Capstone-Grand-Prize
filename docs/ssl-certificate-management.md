# 🔐 SSL 인증서 관리 가이드

> **SEAHAWK 프로젝트 HTTPS 보안 구축 완전 가이드**  
> **작성자**: 신태빈 (서버 보안/시스템 관리 담당)

---

## 📋 개요

SEAHAWK QR 출입/결제 시스템의 SSL/TLS 보안 구현을 위한 완전한 가이드입니다. Let's Encrypt 무료 SSL 인증서를 활용하여 **SSL Labs A+ 등급**을 달성한 실제 구현 방법과 자동화 스크립트를 제공합니다.

### **달성 목표**
- 🏆 **SSL Labs A+ 등급** 달성
- 🔒 **완전한 HTTPS 적용** (모든 통신 구간)
- ⚡ **자동 갱신 시스템** 구축
- 🛡️ **최신 보안 헤더** 적용

---

## 🏗️ 1. 사전 준비사항

### **1.1 도메인 및 DNS 설정**

```bash
# 도메인 설정 확인 (예: qr.pjhpjh.kr)
nslookup qr.pjhpjh.kr
dig qr.pjhpjh.kr A

# 서브도메인 설정 확인
nslookup admin.qr.pjhpjh.kr
nslookup api.qr.pjhpjh.kr
```

### **1.2 필수 패키지 설치**

```bash
# EPEL 저장소 확인
sudo dnf install -y epel-release

# Certbot 및 관련 패키지 설치
sudo dnf install -y certbot python3-certbot-nginx

# Nginx 설치 (아직 설치하지 않은 경우)
sudo dnf install -y nginx

# OpenSSL 최신 버전 확인
openssl version
```

### **1.3 방화벽 설정**

```bash
# HTTP/HTTPS 포트 열기
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# 포트 확인
sudo firewall-cmd --list-services
```

---

## 🔑 2. Let's Encrypt SSL 인증서 발급

### **2.1 Nginx 기본 설정**

```bash
# Nginx 기본 설정 파일 생성
sudo vim /etc/nginx/conf.d/seahawk-http.conf
```

```nginx
# HTTP 기본 설정 (SSL 인증서 발급용)
server {
    listen 80;
    server_name qr.pjhpjh.kr admin.qr.pjhpjh.kr api.qr.pjhpjh.kr;
    
    # Let's Encrypt 인증 경로
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # 나머지 요청은 HTTPS로 리다이렉트 (인증서 발급 후 적용)
    location / {
        return 301 https://$server_name$request_uri;
    }
}
```

```bash
# 웹 루트 디렉터리 생성
sudo mkdir -p /var/www/html

# Nginx 설정 테스트 및 시작
sudo nginx -t
sudo systemctl start nginx
sudo systemctl enable nginx
```

### **2.2 SSL 인증서 발급**

#### **단일 도메인 인증서 발급**

```bash
# 메인 도메인 인증서 발급
sudo certbot certonly \
  --webroot \
  --webroot-path=/var/www/html \
  --email root.bin.vi@gmail.com \
  --agree-tos \
  --no-eff-email \
  -d qr.pjhpjh.kr
```

#### **멀티 도메인 인증서 발급 (권장)**

```bash
# 여러 서브도메인을 포함한 인증서 발급
sudo certbot certonly \
  --webroot \
  --webroot-path=/var/www/html \
  --email root.bin.vi@gmail.com \
  --agree-tos \
  --no-eff-email \
  -d qr.pjhpjh.kr \
  -d admin.qr.pjhpjh.kr \
  -d api.qr.pjhpjh.kr \
  -d pos.qr.pjhpjh.kr
```

### **2.3 인증서 발급 확인**

```bash
# 인증서 파일 확인
sudo ls -la /etc/letsencrypt/live/qr.pjhpjh.kr/

# 인증서 정보 확인
sudo openssl x509 -in /etc/letsencrypt/live/qr.pjhpjh.kr/cert.pem -text -noout

# 인증서 유효 기간 확인
sudo certbot certificates
```

---

## ⚙️ 3. Nginx SSL 설정 최적화

### **3.1 SSL 설정 파일 생성**

```bash
# SSL 전용 설정 파일 생성
sudo vim /etc/nginx/ssl-config.conf
```

```nginx
# SSL 보안 설정 (A+ 등급 달성 설정)

# SSL 프로토콜 버전 (TLS 1.2, 1.3만 허용)
ssl_protocols TLSv1.2 TLSv1.3;

# SSL 암호화 스위트 (최신 보안 기준)
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# 서버 암호화 우선순위 설정
ssl_prefer_server_ciphers off;

# SSL 세션 설정
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP Stapling 활성화
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/qr.pjhpjh.kr/chain.pem;

# DNS 서버 설정
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# DH Parameters 설정
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
```

### **3.2 DH Parameters 생성**

```bash
# SSL 디렉터리 생성
sudo mkdir -p /etc/nginx/ssl

# DH Parameters 생성 (시간이 오래 걸림 - 약 5-10분)
sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048

# 권한 설정
sudo chmod 600 /etc/nginx/ssl/dhparam.pem
```

### **3.3 HTTPS 가상 호스트 설정**

```bash
# HTTPS 메인 설정 파일 생성
sudo vim /etc/nginx/conf.d/seahawk-https.conf
```

```nginx
# SEAHAWK HTTPS 설정
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name qr.pjhpjh.kr;
    
    # SSL 인증서 설정
    ssl_certificate /etc/letsencrypt/live/qr.pjhpjh.kr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/qr.pjhpjh.kr/privkey.pem;
    
    # SSL 보안 설정 포함
    include /etc/nginx/ssl-config.conf;
    
    # 보안 헤더 설정
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;
    
    # 웹 루트 설정
    root /var/www/html;
    index index.html index.htm;
    
    # 메인 위치 설정
    location / {
        try_files $uri $uri/ =404;
    }
    
    # API 프록시 설정 (Node.js)
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    # JSP 프록시 설정 (Tomcat)
    location /jsp/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# 관리자 페이지 HTTPS 설정
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name admin.qr.pjhpjh.kr;
    
    # SSL 인증서 설정
    ssl_certificate /etc/letsencrypt/live/qr.pjhpjh.kr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/qr.pjhpjh.kr/privkey.pem;
    
    # SSL 보안 설정 포함
    include /etc/nginx/ssl-config.conf;
    
    # 보안 헤더 (관리자 페이지용 강화)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # 관리자 페이지 위치
    root /usr/share/nginx/html/admin;
    index index.html;
    
    # IP 접근 제한 (학교 네트워크만 허용)
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    
    location / {
        try_files $uri $uri/ =404;
    }
}

# HTTP에서 HTTPS로 리다이렉트
server {
    listen 80;
    listen [::]:80;
    server_name qr.pjhpjh.kr admin.qr.pjhpjh.kr api.qr.pjhpjh.kr;
    
    # Let's Encrypt 인증 경로
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # HTTPS 강제 리다이렉트
    location / {
        return 301 https://$server_name$request_uri;
    }
}
```

### **3.4 Nginx 설정 테스트 및 재시작**

```bash
# Nginx 설정 문법 검사
sudo nginx -t

# 설정에 문제가 없으면 재시작
sudo systemctl reload nginx

# Nginx 상태 확인
sudo systemctl status nginx
```

---

## 🤖 4. 자동 갱신 시스템 구축

### **4.1 갱신 스크립트 생성**

```bash
# 인증서 갱신 스크립트 생성
sudo vim /usr/local/bin/ssl-renew.sh
```

```bash
#!/bin/bash
# SSL 인증서 자동 갱신 스크립트

LOG_FILE="/var/log/ssl-renewal.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] SSL 인증서 갱신 시작" >> $LOG_FILE

# 인증서 갱신 시도
if /usr/bin/certbot renew --quiet --no-self-upgrade; then
    echo "[$DATE] 인증서 갱신 성공" >> $LOG_FILE
    
    # Nginx 설정 테스트
    if /usr/sbin/nginx -t > /dev/null 2>&1; then
        # Nginx 재로드
        /usr/bin/systemctl reload nginx
        echo "[$DATE] Nginx 재로드 완료" >> $LOG_FILE
    else
        echo "[$DATE] ERROR: Nginx 설정 오류" >> $LOG_FILE
    fi
    
else
    echo "[$DATE] ERROR: 인증서 갱신 실패" >> $LOG_FILE
fi

echo "[$DATE] SSL 갱신 작업 완료" >> $LOG_FILE
echo "---" >> $LOG_FILE
```

```bash
# 스크립트 실행 권한 부여
sudo chmod +x /usr/local/bin/ssl-renew.sh

# 수동 테스트
sudo /usr/local/bin/ssl-renew.sh
```

### **4.2 Cron 자동 실행 설정**

```bash
# crontab 설정
sudo crontab -e
```

```bash
# 매일 새벽 2시에 SSL 인증서 갱신 확인
0 2 * * * /usr/local/bin/ssl-renew.sh

# 매주 일요일 새벽 3시에 전체 갱신 시도
0 3 * * 0 /usr/bin/certbot renew --force-renewal --quiet
```

### **4.3 갱신 확인 스크립트**

```bash
# 인증서 상태 확인 스크립트
sudo vim /usr/local/bin/ssl-check.sh
```

```bash
#!/bin/bash
# SSL 인증서 상태 확인 스크립트

DOMAIN="qr.pjhpjh.kr"
THRESHOLD=30  # 30일 이전 알림

# 인증서 만료일 확인
EXPIRY_DATE=$(echo | openssl s_client -servername $DOMAIN -connect $DOMAIN:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))

echo "SSL 인증서 만료까지: $DAYS_LEFT 일"

if [ $DAYS_LEFT -lt $THRESHOLD ]; then
    echo "경고: SSL 인증서가 $DAYS_LEFT 일 후 만료됩니다!"
    echo "만료일: $EXPIRY_DATE"
fi
```

```bash
# 실행 권한 부여
sudo chmod +x /usr/local/bin/ssl-check.sh

# 테스트 실행
sudo /usr/local/bin/ssl-check.sh
```

---

## 🧪 5. SSL/TLS 보안 테스트

### **5.1 SSL Labs 테스트**

```bash
# 브라우저에서 접속하여 테스트
# https://www.ssllabs.com/ssltest/
# 도메인: qr.pjhpjh.kr 입력
```

### **5.2 로컬 SSL 테스트**

```bash
# OpenSSL을 이용한 SSL 연결 테스트
openssl s_client -connect qr.pjhpjh.kr:443 -servername qr.pjhpjh.kr

# TLS 버전 확인
openssl s_client -connect qr.pjhpjh.kr:443 -tls1_2
openssl s_client -connect qr.pjhpjh.kr:443 -tls1_3

# 인증서 체인 확인
openssl s_client -connect qr.pjhpjh.kr:443 -showcerts
```

### **5.3 테스트 스크립트 활용**

```bash
# testssl.sh 설치 및 실행 (자세한 SSL 분석)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# SSL 종합 테스트 실행
./testssl.sh qr.pjhpjh.kr

# 특정 취약점만 테스트
./testssl.sh --vulnerabilities qr.pjhpjh.kr
./testssl.sh --protocols qr.pjhpjh.kr
./testssl.sh --cipher-per-proto qr.pjhpjh.kr
```

---

## 📊 6. SSL 인증서 모니터링

### **6.1 모니터링 대시보드**

```bash
# 인증서 정보 HTML 리포트 생성
sudo vim /usr/local/bin/ssl-report.sh
```

```bash
#!/bin/bash
# SSL 인증서 상태 HTML 리포트 생성

REPORT_FILE="/var/www/html/ssl-status.html"
DOMAIN="qr.pjhpjh.kr"

cat > $REPORT_FILE << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SEAHAWK SSL Certificate Status</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .status { padding: 20px; margin: 10px 0; border-left: 4px solid #27ae60; }
        .warning { border-left-color: #f39c12; }
        .error { border-left-color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SEAHAWK SSL Certificate Status</h1>
        <p>Last Updated: $(date)</p>
    </div>
EOF

# 인증서 정보 추가
EXPIRY_DATE=$(echo | openssl s_client -servername $DOMAIN -connect $DOMAIN:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
ISSUER=$(echo | openssl s_client -servername $DOMAIN -connect $DOMAIN:443 2>/dev/null | openssl x509 -noout -issuer | cut -d= -f2-)

cat >> $REPORT_FILE << EOF
    <div class="status">
        <h3>📋 Certificate Information</h3>
        <p><strong>Domain:</strong> $DOMAIN</p>
        <p><strong>Issuer:</strong> $ISSUER</p>
        <p><strong>Expiry Date:</strong> $EXPIRY_DATE</p>
    </div>
</body>
</html>
EOF

echo "SSL 상태 리포트 생성 완료: $REPORT_FILE"
```

### **6.2 알림 시스템**

```bash
# 인증서 만료 알림 스크립트
sudo vim /usr/local/bin/ssl-alert.sh
```

```bash
#!/bin/bash
# SSL 인증서 만료 알림 시스템

DOMAIN="qr.pjhpjh.kr"
ALERT_EMAIL="root.bin.vi@gmail.com"
THRESHOLD=14  # 14일 이전 알림

# 인증서 만료일 계산
EXPIRY_DATE=$(echo | openssl s_client -servername $DOMAIN -connect $DOMAIN:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt $THRESHOLD ]; then
    # 시스템 로그에 기록
    logger "SSL Certificate for $DOMAIN expires in $DAYS_LEFT days"
    
    # 메일 발송 (sendmail 설치 필요)
    # echo "SSL Certificate for $DOMAIN expires in $DAYS_LEFT days" | mail -s "SSL Alert" $ALERT_EMAIL
    
    # 또는 간단한 파일 로그
    echo "$(date): SSL Certificate for $DOMAIN expires in $DAYS_LEFT days" >> /var/log/ssl-alerts.log
fi
```

---

## 🔧 7. 고급 SSL 설정

### **7.1 HTTP/2 최적화**

```bash
# Nginx HTTP/2 설정 확인
sudo vim /etc/nginx/conf.d/seahawk-https.conf
```

```nginx
# HTTP/2 Push 설정 (선택사항)
location / {
    # HTTP/2 Server Push
    http2_push /css/style.css;
    http2_push /js/app.js;
    
    try_files $uri $uri/ =404;
}
```

### **7.2 OCSP Stapling 고급 설정**

```bash
# OCSP Stapling 상태 확인
openssl s_client -connect qr.pjhpjh.kr:443 -status

# OCSP 응답 수동 확인
openssl ocsp -issuer /etc/letsencrypt/live/qr.pjhpjh.kr/chain.pem \
             -cert /etc/letsencrypt/live/qr.pjhpjh.kr/cert.pem \
             -text -url http://ocsp.int-x3.letsencrypt.org
```

### **7.3 보안 헤더 고도화**

```nginx
# 고급 보안 헤더 설정
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'none'; worker-src 'none'; frame-ancestors 'none';" always;
```

---

## 🚨 8. 문제 해결 가이드

### **8.1 일반적인 SSL 오류**

#### **인증서 발급 실패**
```bash
# 포트 80이 열려있는지 확인
sudo ss -tulpn | grep :80

# 웹 서버가 실행 중인지 확인
sudo systemctl status nginx

# DNS 레코드 확인
dig qr.pjhpjh.kr A +short

# 방화벽 확인
sudo firewall-cmd --list-all
```

#### **인증서 갱신 실패**
```bash
# 인증서 상태 확인
sudo certbot certificates

# 갱신 시뮬레이션
sudo certbot renew --dry-run

# 로그 확인
sudo tail -f /var/log/letsencrypt/letsencrypt.log
```

#### **SSL 등급이 낮은 경우**
```bash
# 현재 SSL 설정 확인
sudo nginx -T | grep ssl

# 약한 암호화 스위트 제거
ssl_ciphers !aNULL:!MD5:!3DES;
ssl_protocols TLSv1.2 TLSv1.3;
```

### **8.2 긴급 복구 절차**

```bash
# SSL 인증서 백업
sudo tar -czf ssl-backup-$(date +%Y%m%d).tar.gz /etc/letsencrypt/

# 기본 HTTP 설정으로 복구
sudo cp /etc/nginx/conf.d/seahawk-http.conf.backup /etc/nginx/conf.d/seahawk-http.conf
sudo systemctl reload nginx

# 새 인증서 강제 발급
sudo certbot delete --cert-name qr.pjhpjh.kr
sudo certbot certonly --force-renewal -d qr.pjhpjh.kr
```

---

## 📈 9. 성능 및 보안 지표

### **9.1 달성된 보안 등급**

| 항목 | 달성 등급 | 세부 사항 |
|------|-----------|-----------|
| **SSL Labs Rating** | A+ | 최고 보안 등급 |
| **TLS Protocol** | TLS 1.3 | 최신 프로토콜 |
| **Cipher Strength** | 256-bit | 강력한 암호화 |
| **Certificate** | ECC | 타원곡선 암호화 |
| **HSTS** | 활성화 | 강제 HTTPS |
| **OCSP Stapling** | 활성화 | 빠른 인증서 검증 |

### **9.2 성능 최적화 결과**

```bash
# SSL 핸드셰이크 시간 측정
curl -o /dev/null -s -w "SSL handshake: %{time_appconnect}s\nTotal time: %{time_total}s\n" https://qr.pjhpjh.kr/

# HTTP/2 지원 확인
curl -I --http2 https://qr.pjhpjh.kr/
```

---

## ✅ 10. SSL 설정 체크리스트

### **10.1 필수 항목**

- [ ] Let's Encrypt 인증서 발급 완료
- [ ] TLS 1.2/1.3만 허용 설정
- [ ] 강력한 암호화 스위트 설정
- [ ] HSTS 헤더 설정 (최소 1년)
- [ ] OCSP Stapling 활성화
- [ ] HTTP에서 HTTPS 리다이렉트
- [ ] 보안 헤더 전체 적용
- [ ] 자동 갱신 cron 설정
- [ ] SSL Labs A+ 등급 달성
- [ ] 인증서 만료 모니터링 설정

### **10.2 권장 항목**

- [ ] HTTP/2 지원 활성화
- [ ] 인증서 백업 및 복구 절차
- [ ] 멀티 도메인 와일드카드 인증서
- [ ] DNS CAA 레코드 설정
- [ ] 인증서 투명성 로그 모니터링
- [ ] 정기적인 SSL 테스트 자동화

---


**마지막 업데이트**: 2025년 9월 24일  
**문서 버전**: v1.0  
**달성 등급**: SSL Labs A+ / Perfect Forward Secrecy  
**적용 도메인**: qr.pjhpjh.kr
