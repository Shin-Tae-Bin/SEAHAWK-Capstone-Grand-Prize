# 🔐 SSL 인증서 자동 설치 스크립트

> **SEAHAWK 프로젝트 Let's Encrypt SSL 인증서 자동 설치**  
> **작성자**: 신태빈 (서버 보안/시스템 관리 담당)  
> **기반**: 실제 운영 환경 (qr.pjhpjh.kr)

---

## 📋 스크립트 개요

실제 SEAHAWK 프로젝트에서 사용 중인 Let's Encrypt SSL 인증서 자동 설치 및 갱신 시스템을 기반으로 작성된 스크립트입니다.

### **🎯 기능**
- ✅ **Let's Encrypt 인증서 자동 발급**
- ✅ **Nginx 설정 자동 구성**
- ✅ **cron 자동 갱신 설정**
- ✅ **SSL Labs A+ 등급 달성**

---

## 🚀 ssl-setup.sh

```bash
#!/bin/bash
#
# SEAHAWK SSL Certificate Setup Script
# Let's Encrypt 인증서 자동 설치 및 Nginx 설정
#
# 작성자: 신태빈 (root.bin.vi@gmail.com)
# 버전: 1.0
# 최종 수정: 2025-09-24
#

set -e  # 오류 발생시 스크립트 중단

# =============================================================================
# 설정 변수
# =============================================================================
DOMAIN="qr.pjhpjh.kr"
EMAIL="root.bin.vi@gmail.com"
WEBROOT="/var/www/html"
NGINX_CONF_DIR="/etc/nginx/conf.d"
LOG_FILE="/var/log/ssl-setup.log"

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# 로그 함수
# =============================================================================
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_FILE
}

# =============================================================================
# 시스템 확인 함수
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "이 스크립트는 root 권한으로 실행해야 합니다."
    fi
}

check_system() {
    info "시스템 정보 확인 중..."
    
    # OS 확인
    if [ -f /etc/redhat-release ]; then
        OS="Rocky Linux"
        log "운영체제: $OS"
    else
        warning "지원되지 않는 운영체제입니다. Rocky Linux에서 테스트되었습니다."
    fi
    
    # 네트워크 연결 확인
    if ! ping -c 1 google.com &> /dev/null; then
        error "인터넷 연결을 확인해주세요."
    fi
    
    log "시스템 확인 완료"
}

# =============================================================================
# 패키지 설치 함수
# =============================================================================
install_packages() {
    log "필수 패키지 설치 중..."
    
    # EPEL 저장소 설치
    dnf install -y epel-release
    
    # 필수 패키지 설치
    dnf install -y certbot python3-certbot-nginx nginx firewalld
    
    # 서비스 활성화
    systemctl enable nginx
    systemctl enable firewalld
    
    log "패키지 설치 완료"
}

# =============================================================================
# 방화벽 설정 함수
# =============================================================================
setup_firewall() {
    log "방화벽 설정 중..."
    
    # 방화벽 시작
    systemctl start firewalld
    
    # HTTP/HTTPS 포트 열기
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
    
    # 설정 확인
    firewall-cmd --list-services
    
    log "방화벽 설정 완료"
}

# =============================================================================
# Nginx 기본 설정 함수
# =============================================================================
setup_nginx_basic() {
    log "Nginx 기본 설정 구성 중..."
    
    # 웹 루트 디렉터리 생성
    mkdir -p $WEBROOT
    
    # 기본 인덱스 페이지 생성
    cat > $WEBROOT/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SEAHAWK QR System</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
        .logo { color: #2c5f2d; font-size: 2em; font-weight: bold; }
        .subtitle { color: #666; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="logo">🛡️ SEAHAWK</div>
    <div class="subtitle">QR 출입/결제 통합 시스템</div>
    <p>SSL 설정 중입니다...</p>
</body>
</html>
EOF
    
    # 임시 HTTP 설정 파일 생성 (SSL 인증서 발급용)
    cat > $NGINX_CONF_DIR/temp-http.conf << EOF
server {
    listen 80;
    server_name $DOMAIN;
    root $WEBROOT;
    
    # Let's Encrypt 인증 경로
    location /.well-known/acme-challenge/ {
        root $WEBROOT;
    }
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    
    # Nginx 시작
    nginx -t && systemctl start nginx
    
    log "Nginx 기본 설정 완료"
}

# =============================================================================
# SSL 인증서 발급 함수
# =============================================================================
issue_certificate() {
    log "SSL 인증서 발급 중..."
    
    # Let's Encrypt 인증서 발급
    certbot certonly \
        --webroot \
        --webroot-path=$WEBROOT \
        --email $EMAIL \
        --agree-tos \
        --no-eff-email \
        --non-interactive \
        -d $DOMAIN
    
    if [ $? -eq 0 ]; then
        log "SSL 인증서 발급 성공"
        
        # 인증서 정보 확인
        certbot certificates
        
        # 인증서 파일 권한 확인
        ls -la /etc/letsencrypt/live/$DOMAIN/
        
    else
        error "SSL 인증서 발급 실패"
    fi
}

# =============================================================================
# SSL Nginx 설정 함수
# =============================================================================
setup_nginx_ssl() {
    log "SSL Nginx 설정 구성 중..."
    
    # 임시 HTTP 설정 파일 제거
    rm -f $NGINX_CONF_DIR/temp-http.conf
    
    # SEAHAWK 전용 SSL 설정 파일 생성
    cat > $NGINX_CONF_DIR/seahawk-ssl.conf << EOF
# =============================================================================
# SEAHAWK QR 시스템 - SSL 설정
# =============================================================================

# IP 기반 접근 리다이렉트
server {
    listen 80;
    listen 443 ssl;
    server_name $(curl -s ifconfig.me);
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    return 301 https://$DOMAIN\$request_uri;
}

# HTTP → HTTPS 리다이렉트
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

# HTTPS 메인 서버
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    # SSL 인증서 설정
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # SSL 보안 설정 (A+ 등급)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # 보안 헤더
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # 웹 루트 설정
    root $WEBROOT;
    index index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 관리자 페이지 프록시 (포트 3555)
    location /admin/ {
        proxy_pass http://localhost:3555/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Node.js POS 프록시 (포트 3636)
    location /pos_node/ {
        proxy_pass http://localhost:3636/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Tomcat JSP 프록시 (포트 8443)
    location /jsp/ {
        proxy_pass http://localhost:8443/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    # Nginx 설정 테스트 및 재시작
    nginx -t && systemctl reload nginx
    
    log "SSL Nginx 설정 완료"
}

# =============================================================================
# 자동 갱신 설정 함수
# =============================================================================
setup_auto_renewal() {
    log "SSL 인증서 자동 갱신 설정 중..."
    
    # crontab에 갱신 작업 추가
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/certbot renew --quiet --post-hook \"systemctl reload nginx\"") | crontab -
    
    # 갱신 테스트
    certbot renew --dry-run
    
    if [ $? -eq 0 ]; then
        log "자동 갱신 설정 성공"
        crontab -l
    else
        warning "자동 갱신 테스트 실패 - 수동으로 확인이 필요합니다"
    fi
}

# =============================================================================
# SSL 테스트 함수
# =============================================================================
test_ssl() {
    log "SSL 설정 테스트 중..."
    
    # 인증서 유효성 확인
    openssl x509 -in /etc/letsencrypt/live/$DOMAIN/cert.pem -text -noout | grep -E "(Subject|Issuer|Not After)"
    
    # HTTPS 연결 테스트
    if curl -Is https://$DOMAIN | head -1 | grep -q "200 OK"; then
        log "HTTPS 연결 성공"
    else
        warning "HTTPS 연결 확인 필요"
    fi
    
    # SSL Labs 테스트 안내
    info "SSL Labs에서 등급 확인: https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
}

# =============================================================================
# 정리 및 완료 함수
# =============================================================================
cleanup_and_finish() {
    log "설정 완료 및 정리 중..."
    
    # 임시 파일 정리
    rm -f /tmp/ssl-setup-*
    
    # 상태 확인
    systemctl status nginx --no-pager
    
    # 완료 메시지
    cat << EOF

🎉 SEAHAWK SSL 설정이 완료되었습니다!

📊 설정 정보:
   - 도메인: https://$DOMAIN
   - SSL 인증서: Let's Encrypt
   - 자동 갱신: 매일 03:00 (cron)
   - 만료일: $(openssl x509 -in /etc/letsencrypt/live/$DOMAIN/cert.pem -noout -dates | grep notAfter | cut -d= -f2)

🔍 확인 사항:
   1. 웹사이트 접속: https://$DOMAIN
   2. SSL 등급 확인: https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN
   3. 자동 갱신 테스트: certbot renew --dry-run

📞 지원: root.bin.vi@gmail.com

EOF

    log "SEAHAWK SSL 설치 완료!"
}

# =============================================================================
# 메인 실행 함수
# =============================================================================
main() {
    log "🛡️ SEAHAWK SSL 자동 설치 시작"
    log "도메인: $DOMAIN"
    log "이메일: $EMAIL"
    
    check_root
    check_system
    install_packages
    setup_firewall
    setup_nginx_basic
    issue_certificate
    setup_nginx_ssl
    setup_auto_renewal
    test_ssl
    cleanup_and_finish
}

# =============================================================================
# 스크립트 실행
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

---

## 🚀 사용 방법

### **1. 스크립트 실행**

```bash
# 스크립트 다운로드 및 실행 권한 부여
chmod +x ssl-setup.sh

# 도메인과 이메일 수정 후 실행
sudo ./ssl-setup.sh
```

### **2. 수동 설정 (필요시)**

```bash
# 도메인 변경
DOMAIN="your-domain.com"

# 이메일 변경  
EMAIL="your-email@example.com"

# 스크립트 실행
sudo ./ssl-setup.sh
```

### **3. 기존 환경에 적용**

```bash
# 기존 Nginx 설정 백업
sudo cp -r /etc/nginx/conf.d /etc/nginx/conf.d.backup

# 스크립트 실행
sudo ./ssl-setup.sh
```

---

## ⚙️ 실제 적용된 cron 설정

**현재 SEAHAWK 서버에서 실행 중인 자동 갱신:**

```bash
# crontab -l 결과
0 3 * * * /usr/bin/certbot renew --quiet --post-hook "systemctl reload nginx"
```

### **갱신 프로세스**
1. **매일 03:00**에 자동 실행
2. **인증서 만료 30일 전**부터 갱신 시도
3. **갱신 성공시** Nginx 자동 재로드
4. **실패시** 로그 기록 (`/var/log/letsencrypt/`)

---

## 🔍 문제 해결

### **일반적인 오류**

#### **1. 포트 80이 차단된 경우**
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

#### **2. 도메인 DNS 설정 오류**
```bash
# DNS 레코드 확인
nslookup qr.pjhpjh.kr
dig qr.pjhpjh.kr A +short
```

#### **3. 인증서 갱신 실패**
```bash
# 수동 갱신 시도
sudo certbot renew --force-renewal

# 로그 확인
sudo tail -f /var/log/letsencrypt/letsencrypt.log
```

### **갱신 상태 확인**

```bash
# 인증서 정보 확인
sudo certbot certificates

# 갱신 테스트
sudo certbot renew --dry-run

# cron 작업 확인
crontab -l
```

---

## 📊 달성 결과

### **✅ SSL Labs A+ 등급 달성**
- **TLS 1.2/1.3** 최신 프로토콜
- **강력한 암호화 스위트**
- **HSTS 보안 헤더**
- **OCSP Stapling** 활성화

### **⚡ 자동화 시스템**
- **완전 자동 설치** 프로세스
- **인증서 자동 갱신** (90일 주기)
- **Nginx 자동 재로드**
- **오류 처리** 및 로깅

### **🛡️ 보안 강화**
- **IP 직접 접근 차단**
- **HTTP → HTTPS 강제 리다이렉트**
- **보안 헤더 완전 적용**
- **세션 보안 최적화**

---

**마지막 업데이트**: 2025년 9월 24일  
**테스트 환경**: Rocky Linux 9.5 + qr.pjhpjh.kr  
**SSL 등급**: A+ (SSL Labs 기준)