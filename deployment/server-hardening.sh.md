# 🛡️ 서버 보안 강화 스크립트

> **SEAHAWK 프로젝트 Rocky Linux 서버 보안 하드닝**  
> **작성자**: 신태빈 (서버 보안/시스템 관리 담당)  
> **기반**: 실제 운영 환경 보안 설정

---

## 📋 스크립트 개요

SEAHAWK QR 출입/결제 시스템 운영 환경에서 적용된 실제 보안 강화 설정을 기반으로 작성된 서버 하드닝 스크립트입니다.

### **🎯 보안 기능**
- ✅ **SSH 보안 강화** (키 인증, 포트 변경)
- ✅ **사용자 계정 보안** (패스워드 정책, 로그인 제한)
- ✅ **방화벽 설정** (포트 제한, IP 차단)
- ✅ **시스템 보안** (커널 매개변수, 서비스 제한)
- ✅ **로그 모니터링** (fail2ban, 실시간 탐지)

---

## 🚀 server-hardening.sh

```bash
#!/bin/bash
#
# SEAHAWK Server Hardening Script
# Rocky Linux 보안 강화 자동 설정
#
# 작성자: 신태빈 (root.bin.vi@gmail.com)
# 버전: 1.0
# 최종 수정: 2025-09-24
# 기반: 실제 SEAHAWK 서버 운영 환경
#

set -e  # 오류 발생시 스크립트 중단

# =============================================================================
# 설정 변수
# =============================================================================
ADMIN_USER="seahawk"
SSH_PORT="2022"
ADMIN_EMAIL="root.bin.vi@gmail.com"
LOG_FILE="/var/log/server-hardening.log"
BACKUP_DIR="/root/security-backup-$(date +%Y%m%d)"

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

success() {
    echo -e "${PURPLE}[SUCCESS]${NC} $1" | tee -a $LOG_FILE
}

# =============================================================================
# 시스템 확인 및 백업
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "이 스크립트는 root 권한으로 실행해야 합니다."
    fi
}

create_backup() {
    log "설정 파일 백업 중..."
    
    mkdir -p $BACKUP_DIR
    
    # 중요 설정 파일 백업
    cp -r /etc/ssh/ $BACKUP_DIR/ssh_backup/
    cp -r /etc/security/ $BACKUP_DIR/security_backup/
    cp /etc/login.defs $BACKUP_DIR/login.defs.backup
    cp /etc/sysctl.conf $BACKUP_DIR/sysctl.conf.backup 2>/dev/null || true
    
    success "백업 완료: $BACKUP_DIR"
}

# =============================================================================
# SSH 보안 강화
# =============================================================================
harden_ssh() {
    log "SSH 보안 설정 강화 중..."
    
    # SSH 설정 백업
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # SSH 보안 설정 적용
    cat > /etc/ssh/sshd_config << 'EOF'
# SEAHAWK SSH Security Configuration
# 작성자: 신태빈
# 최종 수정: 2025-09-24

# 기본 설정
Port 2022
Protocol 2
AddressFamily inet

# 인증 설정
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# 보안 설정
MaxAuthTries 3
MaxStartups 2
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2

# 사용자 제한 (실제 환경에 맞게 수정)
AllowUsers seahawk

# 기능 제한
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
AllowAgentForwarding no
AllowStreamLocalForwarding no

# 암호화 설정
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# 로그 설정
SyslogFacility AUTHPRIV
LogLevel VERBOSE

# 배너 및 기타
Banner /etc/issue.net
PrintMotd yes
PrintLastLog yes
EOF
    
    # SSH 보안 배너 생성
    cat > /etc/issue.net << 'EOF'
***************************************************************************
                      SEAHAWK QR SYSTEM - AUTHORIZED ONLY
***************************************************************************
WARNING: This system is for authorized personnel only.
All activities on this system are monitored and recorded.
Unauthorized access is prohibited and will be prosecuted.
***************************************************************************
                Contact: root.bin.vi@gmail.com
***************************************************************************
EOF
    
    # SSH 서비스 테스트 및 재시작
    if sshd -t; then
        systemctl restart sshd
        success "SSH 보안 설정 완료"
        
        # 방화벽에서 새 SSH 포트 허용
        firewall-cmd --permanent --remove-service=ssh
        firewall-cmd --permanent --add-port=$SSH_PORT/tcp
        firewall-cmd --reload
        
        warning "SSH 포트가 $SSH_PORT 로 변경되었습니다. 연결이 끊어지지 않도록 주의하세요!"
    else
        error "SSH 설정 오류 - 백업에서 복구하세요: cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config"
    fi
}

# =============================================================================
# 사용자 계정 보안 강화
# =============================================================================
harden_users() {
    log "사용자 계정 보안 강화 중..."
    
    # 관리자 계정 생성 (없는 경우)
    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash $ADMIN_USER
        usermod -aG wheel $ADMIN_USER
        success "관리자 계정 '$ADMIN_USER' 생성 완료"
        
        warning "관리자 계정 비밀번호를 설정하세요: passwd $ADMIN_USER"
    fi
    
    # 패스워드 정책 강화
    cat > /etc/security/pwquality.conf << 'EOF'
# SEAHAWK Password Quality Configuration
# 최소 길이: 12자
minlen = 12

# 문자 클래스 최소 개수: 3개 (대문자, 소문자, 숫자, 특수문자)
minclass = 3

# 동일 문자 반복 제한
maxrepeat = 2

# 동일 클래스 문자 반복 제한
maxclasrepeat = 2

# 각 문자 타입별 최소 개수
dcredit = -1    # 숫자 최소 1개
ucredit = -1    # 대문자 최소 1개  
lcredit = -1    # 소문자 최소 1개
ocredit = -1    # 특수문자 최소 1개

# 사전 단어 사용 금지
dictcheck = 1

# 사용자명 포함 금지
usercheck = 1
EOF
    
    # 로그인 실패 제한 설정
    cat > /etc/security/faillock.conf << 'EOF'
# SEAHAWK Account Lockout Policy
# 실패 허용 횟수
deny = 5

# 잠금 해제 시간 (초) - 15분
unlock_time = 900

# 실패 카운트 간격 (초) - 15분
fail_interval = 900

# 로그 설정
audit = 1
silent = 0
EOF
    
    # 패스워드 만료 정책
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
    
    # 불필요한 시스템 계정 잠금
    for user in games news gopher ftp; do
        if id "$user" &>/dev/null; then
            usermod -L $user 2>/dev/null || true
            info "시스템 계정 '$user' 잠금 처리"
        fi
    done
    
    success "사용자 계정 보안 강화 완료"
}

# =============================================================================
# 방화벽 보안 설정
# =============================================================================
setup_firewall() {
    log "방화벽 보안 설정 중..."
    
    # firewalld 시작 및 활성화
    systemctl enable firewalld
    systemctl start firewalld
    
    # 기본 존을 public으로 설정
    firewall-cmd --set-default-zone=public
    
    # 필요한 서비스만 허용
    firewall-cmd --permanent --remove-service=dhcpv6-client 2>/dev/null || true
    firewall-cmd --permanent --remove-service=cockpit 2>/dev/null || true
    
    # SEAHAWK 서비스 포트 허용
    firewall-cmd --permanent --add-service=http        # 80 (HTTPS 리다이렉트용)
    firewall-cmd --permanent --add-service=https       # 443
    firewall-cmd --permanent --add-port=$SSH_PORT/tcp  # SSH (변경된 포트)
    
    # 내부 서비스 포트 (localhost만 접근 가능하도록 제한)
    # 3555 (Admin), 3636 (Node.js POS), 8443 (Tomcat) - 외부 접근 차단됨
    
    # DDoS 방어를 위한 연결 제한
    firewall-cmd --permanent --add-rich-rule='rule service name="ssh" accept limit value="5/m"'
    firewall-cmd --permanent --add-rich-rule='rule service name="http" accept limit value="25/s"'
    firewall-cmd --permanent --add-rich-rule='rule service name="https" accept limit value="25/s"'
    
    # 설정 적용
    firewall-cmd --reload
    
    # 상태 확인
    firewall-cmd --list-all
    
    success "방화벽 보안 설정 완료"
}

# =============================================================================
# 커널 보안 매개변수 설정
# =============================================================================
harden_kernel() {
    log "커널 보안 매개변수 설정 중..."
    
    # 시스템 보안 설정 파일 생성
    cat > /etc/sysctl.d/99-seahawk-security.conf << 'EOF'
# SEAHAWK Kernel Security Parameters
# 작성자: 신태빈
# 최종 수정: 2025-09-24

# =============================================================================
# 네트워크 보안 설정
# =============================================================================

# ICMP 리다이렉트 비활성화 (MITM 공격 방어)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 소스 라우팅 비활성화 (스푸핑 공격 방어)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# ICMP Echo 응답 비활성화 (정보 수집 방어)
net.ipv4.icmp_echo_ignore_all = 1

# IP 스푸핑 방어
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP SYN 쿠키 활성화 (SYN Flood 공격 방어)
net.ipv4.tcp_syncookies = 1

# IP 포워딩 비활성화 (라우터 기능 차단)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Martian 패킷 로깅 (비정상 패킷 탐지)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ICMP 브로드캐스트 무시
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 잘못된 ICMP 오류 메시지 무시
net.ipv4.icmp_ignore_bogus_error_responses = 1

# TCP 타임스탬프 비활성화 (정보 노출 방지)
net.ipv4.tcp_timestamps = 0

# =============================================================================
# 시스템 보안 설정
# =============================================================================

# Core 덤프 비활성화 (정보 유출 방지)
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0

# Address Space Layout Randomization 활성화
kernel.randomize_va_space = 2

# Kernel pointer 노출 방지
kernel.kptr_restrict = 2

# dmesg 일반 사용자 접근 제한
kernel.dmesg_restrict = 1

# Kernel 로그 접근 제한  
kernel.printk = 3 3 3 3

# ptrace 접근 제한 (디버깅 방지)
kernel.yama.ptrace_scope = 1

# =============================================================================
# 파일 시스템 보안
# =============================================================================

# /tmp 실행 권한 제한용 (별도 마운트 시)
# fs.protected_hardlinks = 1
# fs.protected_symlinks = 1

# =============================================================================
# 메모리 보안
# =============================================================================

# 메모리 오버커밋 제한
vm.overcommit_memory = 2
vm.overcommit_ratio = 80

# Swap 사용 최소화 (메모리 덤프 방지)
vm.swappiness = 10
EOF
    
    # 설정 적용
    sysctl -p /etc/sysctl.d/99-seahawk-security.conf
    
    success "커널 보안 매개변수 설정 완료"
}

# =============================================================================
# 서비스 보안 강화
# =============================================================================
harden_services() {
    log "시스템 서비스 보안 강화 중..."
    
    # 불필요한 서비스 비활성화
    UNNECESSARY_SERVICES=(
        "postfix"
        "cups"
        "avahi-daemon"
        "bluetooth"
        "rpcbind"
        "nfs-client.target"
    )
    
    for service in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-enabled $service &>/dev/null; then
            systemctl disable $service
            systemctl stop $service 2>/dev/null || true
            info "불필요한 서비스 '$service' 비활성화"
        fi
    done
    
    # 필수 서비스만 활성화 확인
    ESSENTIAL_SERVICES=(
        "sshd"
        "nginx"
        "firewalld"
        "chronyd"
        "rsyslog"
    )
    
    for service in "${ESSENTIAL_SERVICES[@]}"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            systemctl enable $service
            info "필수 서비스 '$service' 활성화 확인"
        fi
    done
    
    success "시스템 서비스 보안 강화 완료"
}

# =============================================================================
# 파일 시스템 보안
# =============================================================================
harden_filesystem() {
    log "파일 시스템 보안 강화 중..."
    
    # 중요 디렉터리 권한 설정
    chmod 1777 /tmp
    chmod 1777 /var/tmp
    chmod 755 /var/log
    
    # 중요 설정 파일 권한 제한
    chmod 600 /etc/ssh/sshd_config
    chmod 600 /etc/security/faillock.conf
    chmod 600 /etc/security/pwquality.conf
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    
    # 불필요한 SUID/SGID 파일 찾기 및 제거
    info "SUID/SGID 파일 검사 중..."
    
    # 제거해도 안전한 SUID 파일들
    SAFE_TO_REMOVE=(
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/wall"
        "/usr/bin/write"
    )
    
    for file in "${SAFE_TO_REMOVE[@]}"; do
        if [[ -f "$file" && -u "$file" ]]; then
            chmod -s "$file"
            info "SUID 제거: $file"
        fi
    done
    
    # World-writable 파일 찾기 (검사용)
    WORLD_WRITABLE=$(find / -type f -perm -002 2>/dev/null | head -10)
    if [[ -n "$WORLD_WRITABLE" ]]; then
        warning "World-writable 파일 발견됨. 수동 검토 필요:"
        echo "$WORLD_WRITABLE" | tee -a $LOG_FILE
    fi
    
    success "파일 시스템 보안 강화 완료"
}

# =============================================================================
# 로그 보안 및 모니터링
# =============================================================================
setup_logging() {
    log "로그 보안 및 모니터링 설정 중..."
    
    # fail2ban 설치 및 설정
    if ! command -v fail2ban-server &>/dev/null; then
        dnf install -y epel-release
        dnf install -y fail2ban
    fi
    
    # fail2ban 설정
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 기본 차단 설정
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 192.168.1.0/24

# 알림 설정
destemail = $ADMIN_EMAIL
sendername = SEAHAWK-Security
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/secure
maxretry = 3
bantime = 7200

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req  
logpath = /var/log/nginx/error.log
maxretry = 5
EOF
    
    # fail2ban 시작
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # 로그 로테이션 설정
    cat > /etc/logrotate.d/seahawk-security << 'EOF'
/var/log/secure /var/log/messages /var/log/maillog {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        /bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endrotate
}

/var/log/server-hardening.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF
    
    success "로그 보안 및 모니터링 설정 완료"
}

# =============================================================================
# 보안 상태 점검
# =============================================================================
security_audit() {
    log "보안 상태 점검 중..."
    
    # 보안 점검 스크립트 생성
    cat > /usr/local/bin/seahawk-security-check.sh << 'EOF'
#!/bin/bash
# SEAHAWK 보안 상태 점검 스크립트

echo "=================== SEAHAWK 보안 점검 결과 ==================="
echo "점검 시간: $(date)"
echo ""

echo "1. SSH 설정 확인:"
echo "   - SSH 포트: $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')"
echo "   - Root 로그인: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')"
echo "   - 패스워드 인증: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')"

echo ""
echo "2. 방화벽 상태:"
systemctl is-active firewalld

echo ""
echo "3. 실패한 로그인 시도 (최근 24시간):"
grep "Failed password" /var/log/secure 2>/dev/null | grep "$(date +'%b %d')" | wc -l

echo ""
echo "4. fail2ban 차단 상태:"
fail2ban-client status 2>/dev/null | grep "Currently banned" || echo "fail2ban 비활성화"

echo ""
echo "5. 중요 서비스 상태:"
for service in sshd nginx firewalld fail2ban; do
    echo "   - $service: $(systemctl is-active $service)"
done

echo ""
echo "6. 시스템 업데이트 확인:"
dnf check-update --quiet && echo "   업데이트 없음" || echo "   업데이트 있음"

echo ""
echo "7. SSL 인증서 만료일:"
if [ -f /etc/letsencrypt/live/qr.pjhpjh.kr/cert.pem ]; then
    openssl x509 -in /etc/letsencrypt/live/qr.pjhpjh.kr/cert.pem -noout -dates | grep notAfter | cut -d= -f2
else
    echo "   SSL 인증서 없음"
fi

echo "=============================================================="
EOF
    
    chmod +x /usr/local/bin/seahawk-security-check.sh
    
    # 보안 점검 실행
    /usr/local/bin/seahawk-security-check.sh
    
    success "보안 상태 점검 완료"
}

# =============================================================================
# 정리 및 완료 메시지
# =============================================================================
cleanup_and_finish() {
    log "서버 보안 강화 완료 및 정리 중..."
    
    # 시스템 재부팅 권장 서비스들 재시작
    systemctl daemon-reload
    
    # 완료 메시지
    cat << EOF

🛡️ SEAHAWK 서버 보안 강화가 완료되었습니다!

📊 적용된 보안 설정:
   ✅ SSH 보안 강화 (포트: $SSH_PORT, 키 인증만 허용)
   ✅ 사용자 계정 보안 (패스워드 정책, 로그인 제한)
   ✅ 방화벽 설정 (필수 포트만 허용)
   ✅ 커널 보안 매개변수 (네트워크 공격 방어)
   ✅ 서비스 최적화 (불필요한 서비스 비활성화)
   ✅ 파일 시스템 보안 (권한 제한, SUID 제거)
   ✅ 로그 모니터링 (fail2ban, 침입 탐지)

⚠️  중요 알림:
   1. SSH 포트가 $SSH_PORT 로 변경되었습니다
   2. 현재 SSH 연결을 유지한 상태에서 새 터미널로 연결 테스트하세요
   3. 관리자 계정($ADMIN_USER) 비밀번호를 설정하세요: passwd $ADMIN_USER

🔍 보안 상태 확인:
   - 정기 점검: /usr/local/bin/seahawk-security-check.sh
   - 백업 위치: $BACKUP_DIR

📞 지원: $ADMIN_EMAIL

EOF
    
    success "SEAHAWK 서버 보안 강화 완료!"
    warning "시스템 재부팅을 권장합니다: reboot"
}

# =============================================================================
# 메인 실행 함수
# =============================================================================
main() {
    log "🛡️ SEAHAWK 서버 보안 강화 시작"
    log "관리자 계정: $ADMIN_USER"
    log "SSH 포트: $SSH_PORT"
    log "알림 이메일: $ADMIN_EMAIL"
    
    check_root
    create_backup
    harden_ssh
    harden_users
    setup_firewall
    harden_kernel
    harden_services
    harden_filesystem
    setup_logging
    security_audit
    cleanup_and_finish
}

# =============================================================================
# 스크립트 실행 (대화형 확인)
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "🛡️ SEAHAWK 서버 보안 강화 스크립트"
    echo "이 스크립트는 시스템 보안 설정을 대폭 변경합니다."
    echo ""
    echo "주요 변경사항:"
    echo "- SSH 포트를 $SSH_PORT 로 변경"
    echo "- SSH 패스워드 인증 비활성화 (키 인증만 허용)"
    echo "- 방화벽 활성화 및 포트 제한"
    echo "- 커널 보안 매개변수 적용"
    echo "- 불필요한 서비스 비활성화"
    echo ""
    
    read -p "계속하시겠습니까? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        main "$@"
    else
        echo "스크립트 실행이 취소되었습니다."
        exit 0
    fi
fi
```

---

## 🚀 사용 방법

### **1. 기본 실행**

```bash
# 스크립트 실행 권한 부여
chmod +x server-hardening.sh

# 대화형 실행
sudo ./server-hardening.sh
```

### **2. 설정 변수 수정**

스크립트 상단의 변수들을 환경에 맞게 수정:

```bash
ADMIN_USER="seahawk"                    # 관리자 계정명
SSH_PORT="2022"                         # SSH 포트 번호
ADMIN_EMAIL="root.bin.vi@gmail.com"     # 알림 이메일
```

### **3. 단계별 실행** (선택사항)

```bash
# 특정 함수만 실행하려면 스크립트를 source 후 개별 호출
source server-hardening.sh
create_backup
harden_ssh
# ... 기타 함수들
```

---

## 🔒 적용되는 보안 설정

### **1. SSH 보안 강화**
- 포트 변경 (2022)
- Root 로그인 금지
- 패스워드 인증 비활성화
- 최대 인증 시도 제한 (3회)
- 고급 암호화 설정

### **2. 사용자 계정 보안**
- 패스워드 복잡성 12자 이상
- 로그인 실패 5회 시 15분 잠금
- 패스워드 만료 90일
- 불필요한 시스템 계정 잠금

### **3. 방화벽 설정**
- 필수 포트만 허용 (80, 443, 2022)
- DDoS 방어 연결 제한
- 내부 서비스 포트 보호

### **4. 커널 보안**
- ICMP Ping 차단
- IP 스푸핑 방어
- SYN Flood 공격 방어
- 정보 수집 공격 차단

### **5. 서비스 최적화**
- 불필요한 서비스 비활성화
- 필수 서비스만 실행
- 리소스 사용량 최적화

### **6. 침입 탐지**
- fail2ban 자동 차단
- 실시간 로그 모니터링
- 이메일 알림 시스템

---

## ✅ 보안 점검 도구

스크립트 실행 후 제공되는 점검 도구:

```bash
# 보안 상태 종합 점검
/usr/local/bin/seahawk-security-check.sh

# fail2ban 상태 확인
fail2ban-client status

# 방화벽 규칙 확인
firewall-cmd --list-all

# SSH 설정 확인
sshd -T | grep -E "(port|permitrootlogin|passwordauthentication)"
```

---

**마지막 업데이트**: 2025년 9월 24일  
**테스트 환경**: Rocky Linux 9.5 (SEAHAWK 운영 서버)  
**보안 등급**: Enterprise Level Security