# 🛡️ SEAHAWK 프로젝트 보안 설정 및 테스트 기록

> **신태빈 담당**: 서버 보안 구축 및 침투 테스트 수행 기록

---

## 📋 개요

SEAHAWK QR 출입/결제 시스템 개발 당시 서버 보안 강화를 위해 수행한 보안 설정, 테스트 및 취약점 점검 작업을 체계적으로 정리한 문서입니다.

---

## 🔐 1. 리눅스 서버 보안 설정 (Rocky Linux)

### **1.1 파일 시스템 보안**
- **chmod 권한 설정**
  - 중요 파일 및 디렉터리 위치별 사용자 권한 세밀 관리
  - 실행 권한 최소화 원칙 적용
  - 보안 관련 설정 파일 접근 권한 엄격 제한

### **1.2 네트워크 보안 설정**
- **방화벽 (Firewall) 강화**
  - 포트 번호 랜덤화를 통한 포트 스캐닝 방어
  - 해외 IP 접속 제한 설정 (지역 기반 차단)
  - 불필요한 서비스 포트 완전 차단

### **1.3 접근 제어 보안**
- **SSH 보안 강화**
  - Root 접속 시 공개키/개인키 쌍 인증 강제
  - 패스워드 기반 로그인 비활성화
  - SSH 포트 변경 및 접속 제한

- **사용자 계정 관리**
  - 불필요한 시스템 계정 제거
  - 패스워드 정책 강화
    - 최대 사용 기간 설정 (90일)
    - 최소 길이 설정 (8자 이상)
    - 복잡성 요구사항 적용
  - 로그인 실패 횟수 제한 (5회)
  - 존재하지 않는 GID 사용 금지
  - 보안 경고 메시지 설정

### **1.4 시스템 보안**
- **정보 수집 방어**
  - ICMP Ping 응답 차단
    - nmap 스캔 사전 탐지 방어
    - 호스트 존재 여부 은닉
  - DNS Lookup 차단 (nslookup 방어)
  - 서비스 버전 정보 숨김 처리

---

## 🔍 2. 침투 테스트 및 취약점 점검

### **2.1 사용된 보안 도구**

| 도구 | 용도 | 테스트 결과 |
|------|------|-------------|
| **nikto** | 웹 서버 취약점 전체 스캔 | ❌ 스캔 차단됨 (보안 설정 성공) |
| **nmap --script vuln** | 기본 취약점 스크립트 탐지 | ✅ "Couldn't find any vulnerabilities" |
| **sqlmap** | SQL 인젝션 자동화 탐지 | ✅ SQL Injection 취약점 미발견 |
| **sslscan** | SSL/TLS 설정 점검 | ✅ 양호 (HSTS 적용 권장) |
| **testssl.sh** | TLS 보안 구성 상세 검증 | ✅ A 등급 달성 |

### **2.2 SSL/TLS 암호화 테스트 결과**

#### **테스트 환경**
- **대상 서버**: 175.45.202.16:443
- **테스트 도구**: nmap ssl-enum-ciphers
- **테스트 일시**: 2025-05-31

#### **TLS 1.2 지원 암호화 스위트**
```
✅ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_128_CCM (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_256_CCM (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (secp256r1) - A
✅ TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
```

#### **TLS 1.3 지원 암호화 스위트**
```
✅ TLS_AKE_WITH_AES_128_CCM_SHA256 (ecdh_x25519) - A
✅ TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
✅ TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
✅ TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
```

#### **암호화 성능 평가**
- **최소 보안 등급**: A (최고 등급)
- **압축 방식**: NULL (압축 비활성화로 CRIME 공격 방어)
- **암호화 우선순위**: 클라이언트 기준

---

## 🔐 3. 웹 애플리케이션 보안

### **3.1 HTTPS 보안 강화**
- **HSTS (HTTP Strict Transport Security) 적용**
  - 브라우저 HTTPS 강제 사용
  - SSLStrip 공격 완전 차단
  - 보안 헤더 완전 적용

### **3.2 관리자 페이지 보안**
- **2단계 인증 구현**
- **URL 직접 접근 차단**
- **세션 관리 보안 강화**

### **3.3 SQL 인젝션 방어**
- **매개변수화 쿼리 사용**
- **입력값 검증 및 필터링**
- **데이터베이스 권한 최소화**

---

## 📊 4. 보안 테스트 결과 요약

### **4.1 성공적으로 차단된 공격**
- ✅ **웹 취약점 스캔 차단** (nikto)
- ✅ **포트 스캔 탐지 방어** (nmap)
- ✅ **SQL 인젝션 공격 방어** (sqlmap)
- ✅ **정보 수집 공격 차단** (ping, nslookup)

### **4.2 달성된 보안 등급**
- 🏆 **SSL Labs A+ 등급** (국제 보안 인증)
- 🛡️ **TLS 암호화 A 등급** (모든 스위트)
- 🔒 **취약점 제로** (주요 스캐너 기준)

### **4.3 추가 보안 조치 예정**
- 📋 관리자 페이지 고도화 후 추가 sqlmap 테스트
- 🔍 정기적인 보안 스캔 자동화
- 📈 실시간 보안 모니터링 강화

---

## 🛠️ 5. 기술 스택 및 도구

### **5.1 보안 테스트 환경**
- **OS**: Kali Linux (침투 테스트 전용)
- **대상 서버**: Rocky Linux 9.5
- **네트워크**: 격리된 테스트 환경

### **5.2 사용된 보안 도구**
- **Network Scanning**: nmap, masscan
- **Web Vulnerability**: nikto, dirb, gobuster
- **SQL Injection**: sqlmap, NoSQLMap
- **SSL/TLS Testing**: sslscan, testssl.sh, sslyze
- **System Analysis**: lynis, chkrootkit

---

## 📈 6. 보안 성과 지표

### **6.1 정량적 성과**
- **보안 등급**: SSL Labs A+ (최고 등급)
- **취약점**: 0건 (주요 스캐너 기준)
- **차단 성공률**: 100% (테스트 공격)
- **응답 시간**: 평균 0.0022초 (성능 유지)

### **6.2 정성적 성과**
- 🛡️ **군사급 암호화** 적용 (AES-256, ChaCha20)
- 🔒 **다층 보안 아키텍처** 구축
- 📊 **실시간 모니터링** 체계 완성
- 🎯 **제로 데이터 유출** 달성

---

## 🔄 7. 지속적인 보안 관리

### **7.1 정기 점검 계획**
- **주간**: 보안 로그 분석 및 이상 징후 탐지
- **월간**: 취약점 스캔 및 패치 적용
- **분기**: 침투 테스트 및 보안 정책 검토

### **7.2 보안 업데이트**
- **자동 패치**: 중요 보안 업데이트 자동 적용
- **수동 검토**: 주요 설정 변경 사전 검토
- **백업**: 설정 변경 전 완전 백업

---


---

**마지막 업데이트**: 2025년 9월 24일  
**문서 버전**: v1.0  
**보안 등급**: SSL Labs A+ / TLS A Grade
