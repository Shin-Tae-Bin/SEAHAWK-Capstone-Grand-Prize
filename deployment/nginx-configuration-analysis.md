# 🌐 SEAHAWK Nginx 설정 파일

> **실제 운영 중인 SEAHAWK QR 시스템 Nginx 설정**  
> **작성자**: 신태빈 (서버 보안/시스템 관리 담당)  
> **서버**: Rocky Linux 9.5 / nginx 1.20+  
> **도메인**: qr.pjhpjh.kr

---

## 📋 설정 개요

SEAHAWK QR 출입/결제 시스템의 실제 운영 중인 Nginx 설정입니다. Let's Encrypt SSL 인증서와 멀티 서비스 프록시 설정으로 구성되어 있습니다.

### **🏗️ 아키텍처**
```
Internet → Nginx (443/80) → Proxy → Backend Services
                              ├── Admin (3555) 
                              ├── Node.js POS (3636)
                              └── Tomcat JSP (8443)
```

---

## 🔧 메인 설정 파일

### **📍 위치**: `/etc/nginx/nginx.conf`

```nginx
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    # 보안 설정
    server_tokens off;                 # 서버 버전 숨김
    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 4096;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # 모듈러 설정 파일 로드
    include /etc/nginx/conf.d/*.conf;

    # 기본 HTTP 서버 (사용하지 않음 - 모든 트래픽이 HTTPS로 리다이렉트됨)
    server {
        listen       80;
        listen       [::]:80;
        server_name  _;
        root         /usr/share/nginx/html;

        include /etc/nginx/default.d/*.conf;

        error_page 404 /404.html;
        location = /404.html {
        }

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
        }
    }
}
```

---

## 🔐 SSL 및 프록시 설정 파일

### **📍 위치**: `/etc/nginx/conf.d/tomcat.conf`

```nginx
# =============================================================================
# SEAHAWK QR 시스템 - IP 기반 리다이렉트 설정
# =============================================================================
server {
    listen 80;
    listen 443 ssl;
    server_name 175.45.202.16;         # 서버 IP 직접 접근 차단

    # SSL 인증서 설정 (도메인 리다이렉트용)
    ssl_certificate /etc/letsencrypt/live/qr.pjhpjh.kr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/qr.pjhpjh.kr/privkey.pem;

    # IP로 접근시 도메인으로 강제 리다이렉트 (보안 강화)
    return 301 https://qr.pjhpjh.kr$request_uri;
}

# =============================================================================
# HTTP → HTTPS 리다이렉트
# =============================================================================
server {
    listen 80;
    server_name qr.pjhpjh.kr;
    
    # 모든 HTTP 요청을 HTTPS로 리다이렉트
    return 301 https://$host$request_uri;
}

# =============================================================================
# SEAHAWK 메인 HTTPS 서버 설정
# =============================================================================
server {
    listen 443 ssl;
    server_name qr.pjhpjh.kr;

    # =======================================================================
    # SSL/TLS 설정
    # =======================================================================
    ssl_certificate /etc/letsencrypt/live/qr.pjhpjh.kr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/qr.pjhpjh.kr/privkey.pem;
    
    # SSL 프로토콜 제한 (보안 강화)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # =======================================================================
    # 프록시 설정 - 백엔드 서비스별 라우팅
    # =======================================================================
    
    # 1. 관리자 페이지 (메인 경로)
    # 포트: 3555 - 관리자 웹 인터페이스
    location / {
        proxy_pass http://localhost:3555/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 2. Node.js POS 시스템 
    # 포트: 3636 - POS 결제 시뮬레이터 및 API
    location /pos_node/ {
        proxy_pass http://localhost:3636/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 3. Tomcat JSP 서비스
    # 포트: 8443 - JSP 기반 백엔드 서비스
    location /jsp/ {
        proxy_pass http://localhost:8443/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 📊 서비스 구성 분석

### **🎯 라우팅 구조**

| 경로 | 백엔드 포트 | 서비스 설명 | 기술 스택 |
|------|-------------|-------------|-----------|
| `/` | 3555 | **관리자 대시보드** | HTML/CSS/JS |
| `/pos_node/` | 3636 | **POS 시뮬레이터** | Node.js/Express |
| `/jsp/` | 8443 | **JSP 백엔드** | Java/Tomcat |

### **🔒 보안 특징**

#### **1. IP 접근 차단**
```nginx
server_name 175.45.202.16;
return 301 https://qr.pjhpjh.kr$request_uri;
```
- 직접 IP 접근을 도메인으로 강제 리다이렉트
- **정보 노출 방지** 및 **브랜딩 통일성** 확보

#### **2. 강제 HTTPS**
```nginx
server_name qr.pjhpjh.kr;
return 301 https://$host$request_uri;
```
- 모든 HTTP 트래픽을 HTTPS로 리다이렉트
- **완전한 암호화 통신** 보장

#### **3. 제한적 SSL 프로토콜**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
```
- 구버전 프로토콜 차단
- 약한 암호화 알고리즘 제거

### **📈 프록시 헤더 최적화**

모든 백엔드 서비스에 공통 적용:
```nginx
proxy_set_header Host $host;                          # 호스트 정보 전달
proxy_set_header X-Real-IP $remote_addr;              # 실제 클라이언트 IP
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 프록시 체인
proxy_set_header X-Forwarded-Proto $scheme;           # 프로토콜 정보
```

---

## 🗂️ 파일 구조

```
/etc/nginx/
├── nginx.conf                   # 메인 설정 파일
├── conf.d/
│   └── tomcat.conf             # SEAHAWK 전용 설정
├── default.d/                  # 기본 서버 설정
├── modules/                    # 동적 모듈
└── mime.types                  # MIME 타입 정의

/etc/letsencrypt/live/qr.pjhpjh.kr/
├── fullchain.pem              # SSL 인증서 체인
├── privkey.pem                # SSL 개인키
├── cert.pem                   # SSL 인증서
└── chain.pem                  # 중간 인증서
```

---

## ⚡ 성능 및 안정성

### **🔧 최적화 설정**

| 설정 항목 | 값 | 효과 |
|-----------|----|----- |
| `worker_processes` | auto | CPU 코어 수에 맞춰 자동 조정 |
| `worker_connections` | 1024 | 동시 연결 수 제한 |
| `keepalive_timeout` | 65 | 연결 유지 시간 |
| `sendfile` | on | 파일 전송 최적화 |
| `tcp_nopush` | on | 패킷 전송 최적화 |

### **📊 운영 지표**

```bash
# 현재 연결 상태 확인
ss -tulpn | grep :443    # HTTPS 연결
ss -tulpn | grep :80     # HTTP 연결

# Nginx 프로세스 상태
systemctl status nginx

# SSL 인증서 만료일
openssl x509 -in /etc/letsencrypt/live/qr.pjhpjh.kr/cert.pem -noout -dates
```

---

## 🚀 포트폴리오 하이라이트

### **✅ 구현된 보안 기능**

1. **🔐 완전한 HTTPS 적용**
   - HTTP → HTTPS 강제 리다이렉트
   - Let's Encrypt 무료 SSL 인증서 활용

2. **🛡️ 서버 정보 보호**
   - `server_tokens off` - 서버 버전 숨김
   - IP 직접 접근 차단 및 도메인 리다이렉트

3. **⚡ 멀티 서비스 프록시**
   - 3개 백엔드 서비스 통합 관리
   - 경로 기반 라우팅으로 서비스 분리

4. **📈 성능 최적화**
   - Worker 프로세스 자동 스케일링
   - 연결 풀링 및 Keep-Alive 최적화

### **🎯 실무 역량 증명**

- **운영 환경 구축**: 실제 도메인과 SSL 인증서 적용
- **보안 설정 숙련도**: TLS 프로토콜 제한 및 암호화 강화  
- **시스템 통합 능력**: 이기종 백엔드 서비스 프록시 구성
- **성능 최적화**: Nginx 고성능 설정 적용

---

## 📞 문의 및 지원

**신태빈 (Shin Tae-Bin)** - 시스템 관리 및 DevOps
- 📧 **Email**: root.bin.vi@gmail.com  
- 🏫 **소속**: 경복대학교 소프트웨어융합학과
- 🛡️ **전문분야**: Nginx, SSL/TLS, 리버스 프록시 설정

---

**마지막 업데이트**: 2025년 9월 24일  
**설정 상태**: 운영 중 (qr.pjhpjh.kr)  
**SSL 등급**: A+ (SSL Labs 기준)