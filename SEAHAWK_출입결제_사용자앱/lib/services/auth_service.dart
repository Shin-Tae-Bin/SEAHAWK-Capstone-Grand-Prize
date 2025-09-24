import 'dart:convert';
import 'package:http/http.dart' as http;
import '../services/api_constants.dart';

class AuthService {
  static Future<Map<String, dynamic>> login(String id, String pw) async {
    print("입력된 ID: $id");
    print("입력된 PW: $pw");  

    final response = await http.post(
      Uri.parse(ApiConstants.login),
      headers: {
        "Content-Type": "application/json",
      },
      body: jsonEncode({
        'id': id,
        'pw': pw,
      }),
    );

    print("서버 응답 코드: ${response.statusCode}");
    print("서버 응답 내용: ${response.body}");

    if (response.statusCode == 200) {
      try {
        final Map<String, dynamic> responseData = jsonDecode(response.body.trim());
        return responseData;
      } catch (e) {
        print("응답 JSON 파싱 실패: $e");
        return {"status": "fail"};
      }
    }
    return {"status": "fail"};
  }
}
