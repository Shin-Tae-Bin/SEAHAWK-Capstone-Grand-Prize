class ApiConstants {
  static const String baseUrl = "https://qr.pjhpjh.kr/jsp";

  // 인증 관련
  static const String login = "$baseUrl/login.jsp";
  static const String logout = "$baseUrl/logout.jsp";

  // 사용자용 기능
  static const String menu = "$baseUrl/api/menus";
  static const String pay = "$baseUrl/pay.jsp";
  static const String menuweek = "$baseUrl/menu_week.jsp";

  // QR 발급 (텍스트 데이터 반환)
  static const String qrGenerate =
      "$baseUrl/qr.jsp"; // QR 문자열(id|hash|timestamp) 반환
  static const String generatePaymentQr =
      "$baseUrl/generate_qr.jsp"; // 서버에서 결제용 QR 생성
  static const String qrImage = "$baseUrl/qr_image.jsp"; // 이미지 생성

  // 관리자용 기능
  static const String verifyQr = "$baseUrl/verify_qr.jsp"; // QR 검증 및 로그 기록
  static const String adminpayLogs = 
      "$baseUrl/admin_get_payment_log.jsp"; // 결제 로그 조회
  static const String ticketUsageLog = "$baseUrl/admin_logs.jsp"; // 식권 사용내역 조회

  static const String userPayLog = "$baseUrl/user_pay_log.jsp"; // 사용자별 결제 로그 조회

  static const String userpoint = "$baseUrl/user_point.jsp"; // 유저 충전 및 환불 내역 조회

  // ✅ 추가된 부분: 포인트 관련 API
  static const String getUserPoints =
      "$baseUrl/get_user_points.jsp"; // 포인트 조회 API
  static const String addPoints =
      "$baseUrl/add_points.jsp"; // 포인트 충전 API (직접 충전 방식)
  static const String pointsHistory =
      "$baseUrl/points_history.jsp"; // 포인트 충전 내역
  static const String refundPoints = "$baseUrl/refund_points.jsp"; // 환불 API 추가
  static const String getPointTransactions =
      "$baseUrl/get_point_transactions.jsp"; // 포인트 거래 내역

  // ✅ 보안 관련
  static const String secretKey = "YOUR_SECRET_KEY"; // 서버와 통신할 때 사용하는 비밀 키
  static const String posAuthToken = "YOUR_AUTH_TOKEN"; // POS 인증용 토큰

  // ✅ 추가된 소속 목록 API
  static const String affiliations = "$baseUrl/get_affiliations.jsp";
  // ✅ 사용자별 식권 사용내역 API
  static const String userTicketUsageLog =
      "$baseUrl/user_ticket_usage_log.jsp"; // 사용자 식권 사용내역
}
