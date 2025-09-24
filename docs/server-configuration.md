# 🖥️ SEAHAWK 프로젝트 서버 설정 상세 가이드

> **Rocky Linux 9.5 기반 프로덕션 서버 보안 설정**  
> **작성자**: 신태빈 (서버 보안/시스템 관리 담당)

---

## 📋 개요

SEAHAWK QR 출입/결제 시스템을 위한 Rocky Linux 9.5 서버의 보안 강화 설정 가이드입니다. 프로덕션 환경에서 안전한 서비스 운영을 위한 필수 보안 설정을 단계별로 제공합니다.

---

## 🏗️ 1. 서버 기본 환경 설정

### **1.1 시스템 업데이트**

```bash
# 시스템 패키지 업데이트
sudo dnf update -y

# EPEL 저장소 설치
sudo dnf install -y epel-release

# 필수 개발 도구 설치
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y wget curl vim git htop
```

### **1.2 시간대 설정**

```bash
# 한국 시간대로 설정
sudo timedatectl set-timezone Asia/Seoul

# NTP 동기화 활성화
sudo timedatectl set-ntp true

# 시간 확인
timedatectl status
```

### **1.3 호스트명 설정**

```bash
# 호스트명 설정
sudo hostnamectl set-hostname seahawk-server

# hosts 파일 편집
sudo vim /etc/hosts
```

```bash
# /etc/hosts 내용
127.0.0.1   localhost seahawk-server
::1         localhost seahawk-server
```

---

## 👥 2. 사용자 계정 관리 및 보안

### **2.1 관리 사용자 계정 생성**

```bash
# 서비스 관리용 계정 생성
sudo useradd -m -s /bin/bash seahawk
sudo usermod -aG wheel seahawk

# 비밀번호 설정
sudo passwd seahawk
```

### **2.2 사용자 계정 보안 정책**

#### **비밀번호 정책 강화**

```bash
# /etc/security/pwquality.conf 편집
sudo vim /etc/security/pwquality.conf
```

```bash
# 비밀번호 복잡성 설정
minlen = 12
minclass = 3
maxrepeat = 2
maxclasrepeat = 2
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
```

#### **계정 잠금 정책 설정**

```bash
# /etc/security/faillock.conf 편집
sudo vim /etc/security/faillock.conf
```

```bash
# 로그인 실패 제한 설정
deny = 5
unlock_time = 900
fail_interval = 900
```

#### **패스워드 만료 정책**

```bash
# /etc/login.defs 편집
sudo vim /etc/login.defs
```

```bash
# 패스워드 만료 설정
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
PASS_MIN_LEN    12
```

### **2.3 불필요한 시스템 계정 관리**

```bash
# 시스템 계정 확인
cat /etc/passwd | grep -E ":(\/usr)?\/s?bin\/(nologin|false)$"

# 불필요한 서비스 계정 잠금 (예시)
sudo usermod -L games
sudo usermod -L news
sudo usermod -L gopher
```

---

## 🔐 3. SSH 보안 강화

### **3.1 SSH 키 쌍 생성**

```bash
# 클라이언트에서 RSA 키 쌍 생성 (4096비트)
ssh-keygen -t rsa -b 4096 -C "seahawk-server-key"

# 또는 더 안전한 Ed25519 키 생성
ssh-keygen -t ed25519 -C "seahawk-server-key"

# 공개키를 서버에 복사
ssh-copy-id -i ~/.ssh/id_rsa.pub seahawk@server_ip
```

### **3.2 SSH 서버 설정 강화**

```bash
# SSH 설정 파일 백업
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# SSH 설정 편집
sudo vim /etc/ssh/sshd_config
```

```bash
# /etc/ssh/sshd_config 보안 설정
# 기본 설정 변경
Port 2022                           # 기본 포트 변경
PermitRootLogin no                  # Root 로그인 금지
PasswordAuthentication no           # 패스워드 인증 비활성화
PubkeyAuthentication yes            # 공개키 인증만 허용
AuthorizedKeysFile .ssh/authorized_keys

# 추가 보안 설정
Protocol 2                          # SSH 프로토콜 버전 2만 사용
MaxAuthTries 3                      # 인증 시도 제한
ClientAliveInterval 300             # 클라이언트 연결 유지 시간
ClientAliveCountMax 2               # 무응답 허용 횟수
MaxStartups 2                       # 동시 연결 제한

# 허용 사용자 제한
AllowUsers seahawk                  # 특정 사용자만 허용

# 기타 보안 설정
X11Forwarding no                    # X11 포워딩 비활성화
AllowTcpForwarding no              # TCP 포워딩 비활성화
GatewayPorts no                     # 게이트웨이 포트 비활성화
PermitTunnel no                     # 터널링 비활성화
```

### **3.3 SSH 서비스 재시작 및 확인**

```bash
# SSH 설정 문법 검사
sudo sshd -t

# SSH 서비스 재시작
sudo systemctl restart sshd

# SSH 서비스 상태 확인
sudo systemctl status sshd

# 방화벽에서 새 SSH 포트 허용
sudo firewall-cmd --permanent --add-port=2022/tcp
sudo firewall-cmd --reload
```

---

## 🔥 4. 방화벽 설정

### **4.1 Firewalld 기본 설정**

```bash
# Firewalld 서비스 시작 및 활성화
sudo systemctl start firewalld
sudo systemctl enable firewalld

# 기본 존 설정 확인
sudo firewall-cmd --get-default-zone

# 공개 존을 기본으로 설정
sudo firewall-cmd --set-default-zone=public
```

### **4.2 서비스 포트 설정**

```bash
# SEAHAWK 프로젝트 필수 포트 열기
sudo firewall-cmd --permanent --add-port=2022/tcp    # SSH
sudo firewall-cmd --permanent --add-port=80/tcp      # HTTP
sudo firewall-cmd --permanent --add-port=443/tcp     # HTTPS
sudo firewall-cmd --permanent --add-port=3306/tcp    # MySQL (내부 접근만)
sudo firewall-cmd --permanent --add-port=8080/tcp    # Tomcat JSP
sudo firewall-cmd --permanent --add-port=3000/tcp    # Node.js

# 설정 적용
sudo firewall-cmd --reload

# 열려있는 포트 확인
sudo firewall-cmd --list-all
```

### **4.3 IP 기반 접근 제한**

```bash
# 신뢰할 수 있는 IP 대역만 허용 (예: 학교 네트워크)
sudo firewall-cmd --permanent --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --add-source=10.0.0.0/8

# 특정 국가 IP 차단 (중국, 러시아 등 - 선택사항)
# GeoIP 기반 차단은 별도 스크립트 필요

# DDoS 방어를 위한 연결 제한
sudo firewall-cmd --permanent --add-rich-rule='rule service name="ssh" accept limit value="5/m"'
```

---

## 🛡️ 5. 시스템 보안 강화

### **5.1 커널 매개변수 보안 설정**

```bash
# /etc/sysctl.d/99-security.conf 생성
sudo vim /etc/sysctl.d/99-security.conf
```

```bash
# 네트워크 보안 설정
# ICMP 리다이렉트 비활성화
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# 소스 라우팅 비활성화
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# ICMP Ping 응답 비활성화 (정보 수집 방어)
net.ipv4.icmp_echo_ignore_all = 1

# IP 스푸핑 방어
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP SYN 쿠키 활성화 (SYN Flood 방어)
net.ipv4.tcp_syncookies = 1

# IP 포워딩 비활성화
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 로그 마틴스 공격 방어
net.ipv4.conf.all.log_martians = 1
```

```bash
# 설정 적용
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

### **5.2 파일 시스템 보안**

#### **중요 디렉터리 권한 설정**

```bash
# /tmp 디렉터리 보안 설정
sudo chmod 1777 /tmp

# /var/tmp 디렉터리 보안 설정  
sudo chmod 1777 /var/tmp

# 중요 설정 파일 권한 제한
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 600 /etc/security/faillock.conf
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/shadow
```

#### **불필요한 SUID/SGID 비트 제거**

```bash
# SUID/SGID 파일 검색
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

# 불필요한 SUID 비트 제거 (예시)
sudo chmod -s /usr/bin/chsh
sudo chmod -s /usr/bin/chfn
sudo chmod -s /usr/bin/wall
```

### **5.3 서비스 관리**

#### **불필요한 서비스 비활성화**

```bash
# 활성 서비스 확인
systemctl list-unit-files --type=service --state=enabled

# 불필요한 서비스 비활성화
sudo systemctl disable postfix    # 메일 서비스
sudo systemctl disable cups       # 프린터 서비스
sudo systemctl disable avahi-daemon  # Zeroconf 서비스
sudo systemctl disable bluetooth  # 블루투스 서비스

# 서비스 중지
sudo systemctl stop postfix
sudo systemctl stop cups
sudo systemctl stop avahi-daemon
sudo systemctl stop bluetooth
```

---

## 📊 6. 로깅 및 감사

### **6.1 시스템 로그 설정**

```bash
# rsyslog 설정 강화
sudo vim /etc/rsyslog.conf
```

```bash
# 로그 설정 추가
# 인증 실패 로그 별도 저장
auth,authpriv.*                    /var/log/auth.log

# 중요 시스템 이벤트 로그
*.emerg                            /var/log/emergency.log
```

### **6.2 로그 보관 정책**

```bash
# logrotate 설정
sudo vim /etc/logrotate.d/seahawk-security
```

```bash
# 보안 로그 로테이션 설정
/var/log/auth.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}

/var/log/emergency.log {
    daily  
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
```

### **6.3 실시간 로그 모니터링**

```bash
# fail2ban 설치 및 설정
sudo dnf install -y fail2ban

# fail2ban 설정 파일 생성
sudo vim /etc/fail2ban/jail.local
```

```bash
[DEFAULT]
# 기본 설정
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 192.168.1.0/24

[sshd]
enabled = true
port = 2022
filter = sshd
logpath = /var/log/secure
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 3
```

```bash
# fail2ban 서비스 시작
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## 🔍 7. 보안 점검 스크립트

### **7.1 자동 보안 점검 스크립트**

```bash
# 보안 점검 스크립트 생성
sudo vim /usr/local/bin/security-check.sh
```

```bash
#!/bin/bash
# SEAHAWK 서버 보안 점검 스크립트

LOG_FILE="/var/log/security-check.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] 보안 점검 시작" >> $LOG_FILE

# 1. 실패한 로그인 시도 확인
echo "=== 실패한 로그인 시도 ===" >> $LOG_FILE
grep "Failed password" /var/log/secure | tail -10 >> $LOG_FILE

# 2. 루트 로그인 시도 확인
echo "=== 루트 로그인 시도 ===" >> $LOG_FILE
grep "root" /var/log/secure | grep -E "(Failed|Invalid)" | tail -5 >> $LOG_FILE

# 3. 시스템 리소스 확인
echo "=== 시스템 리소스 ===" >> $LOG_FILE
df -h >> $LOG_FILE
free -h >> $LOG_FILE

# 4. 네트워크 연결 확인
echo "=== 네트워크 연결 ===" >> $LOG_FILE
ss -tulpn | grep LISTEN >> $LOG_FILE

# 5. 최근 사용자 로그인 확인
echo "=== 최근 로그인 ===" >> $LOG_FILE
last -n 10 >> $LOG_FILE

echo "[$DATE] 보안 점검 완료" >> $LOG_FILE
echo "---" >> $LOG_FILE
```

```bash
# 스크립트 실행 권한 부여
sudo chmod +x /usr/local/bin/security-check.sh

# crontab에 정기 실행 등록
sudo crontab -e
```

```bash
# 매일 02:00에 보안 점검 실행
0 2 * * * /usr/local/bin/security-check.sh
```

---

## 📈 8. 성능 및 보안 모니터링

### **8.1 시스템 모니터링 도구 설치**

```bash
# htop, iotop, nethogs 설치
sudo dnf install -y htop iotop nethogs

# 시스템 정보 확인 도구
sudo dnf install -y neofetch
```

### **8.2 보안 스캔 도구**

```bash
# ClamAV 안티바이러스 설치
sudo dnf install -y clamav clamd

# 바이러스 정의 업데이트
sudo freshclam

# 시스템 스캔
sudo clamscan -r /home /var/www
```

---

## ✅ 9. 보안 설정 체크리스트

### **9.1 필수 보안 항목**

- [ ] 시스템 패키지 최신 업데이트
- [ ] 불필요한 서비스 비활성화
- [ ] SSH 보안 강화 (키 인증, 포트 변경)
- [ ] 방화벽 설정 및 활성화
- [ ] 사용자 계정 보안 정책 적용
- [ ] 커널 보안 매개변수 설정
- [ ] 로그 모니터링 및 보관 정책
- [ ] fail2ban 침입 차단 시스템
- [ ] 정기 보안 점검 스크립트

### **9.2 추가 보안 권장사항**

- [ ] 정기적인 보안 업데이트 적용
- [ ] 백업 시스템 구축
- [ ] 네트워크 분할 및 접근 제어
- [ ] 웹 애플리케이션 방화벽 (WAF) 적용
- [ ] 보안 인증서 정기 갱신
- [ ] 침입 탐지 시스템 (IDS) 구축

---

## 🚨 10. 보안 사고 대응

### **10.1 사고 대응 절차**

```bash
# 긴급 상황시 서버 격리
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP
sudo iptables -I INPUT 1 -s [관리자IP] -j ACCEPT

# 로그 백업
sudo tar -czf /backup/security-logs-$(date +%Y%m%d).tar.gz /var/log/

# 프로세스 확인
ps aux | grep -E "(nc|netcat|wget|curl)"
```

### **10.2 복구 절차**

```bash
# 시스템 상태 확인
sudo systemctl status sshd nginx mysql

# 설정 파일 무결성 확인
sudo rpm -Va | grep '^..5'

# 네트워크 연결 상태 확인
sudo netstat -tulpn | grep LISTEN
```

---

**마지막 업데이트**: 2025년 9월 24일  
**문서 버전**: v1.0  
**적용 환경**: Rocky Linux 9.5 (SEAHAWK 프로덕션 서버)
