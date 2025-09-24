// 이 파일은 사용자의 로그인을 처리하는 페이지입니다.
// 사용자는 학번/사번과 비밀번호를 입력하여 로그인할 수 있습니다.
// 로그인 시도 시 `AuthService`를 통해 서버와 통신하며,
// 성공 시 사용자 정보를 SharedPreferences에 저장하고 QR 스크린으로 이동합니다.
// 실패 시 화면에 에러 메시지를 표시하고, 아이디/비밀번호 찾기 기능도 제공합니다.

import 'package:flutter/material.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/auth_service.dart';
import 'qr_screen.dart';
import 'package:url_launcher/url_launcher.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({Key? key}) : super(key: key);

  @override
  _LoginScreenState createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final idController = TextEditingController();
  final pwController = TextEditingController();
  String message = '';
  bool _obscurePassword = true;
  bool _isLoading = false;

  Future<void> login() async {
    if (_isLoading) return;
    setState(() {
      _isLoading = true;
      message = '';
    });

    final id = idController.text.trim();
    final pw = pwController.text;

    final result = await AuthService.login(id, pw);

    final prefs = await SharedPreferences.getInstance();

    if (result['status'] == "success") {
      await prefs.setString('jwt_token', result['token']);
      await prefs.setString('user_id', result['id']);
      await prefs.setString('user_name', result['name']);
      await prefs.setString('affiliation', result['affiliation']);
      await prefs.setString('profile_image', result['profile_image']);
      await prefs.setString('user_type', 'user');

      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(
          builder:
              (_) => QRScreen(
                userId: result['id'],
                userName: result['name'],
                affiliation: result['affiliation'],
                profileImage: result['profile_image'],
              ),
        ),
      );
    } else if (result['status'] == "admin_success") {
      await prefs.setString('jwt_token', result['token']);
      await prefs.setString('user_id', result['id']);
      await prefs.setString('user_name', result['name']);
      await prefs.setString('user_type', 'admin');
      // 관리자 전용 화면이 있다면 여기에 이동 처리
    } else {
      await prefs.remove('jwt_token');
      await prefs.remove('user_id');
      await prefs.remove('user_name');
      await prefs.remove('user_type');
      await prefs.remove('profile_image');
      await prefs.remove('affiliation');

      setState(() {
        message = "사번,학번 또는 비밀번호가 잘못 되었습니다.\n아이디와 비밀번호를 다시 한 번 확인해주세요.";
      });
    }

    setState(() {
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    ScreenUtil.init(context, designSize: const Size(390, 844));

    return Scaffold(
      backgroundColor: const Color.fromARGB(250, 255, 255, 255),
      appBar: PreferredSize(
        preferredSize: Size.fromHeight(82.h),
        child: Material(
          elevation: 0.15,
          shadowColor: Colors.grey,
          child: Container(
            padding: EdgeInsets.only(top: MediaQuery.of(context).padding.top),
            color: Colors.white,
            child: Center(
              child: Container(
                width: double.infinity,
                height: 82.h,
                padding: EdgeInsets.symmetric(vertical: 16.h, horizontal: 20.w),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Image.asset(
                      'images/kbu_logo.png',
                      height: 50.h,
                      width: 300.w,
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
      body: SingleChildScrollView(
        physics: const NeverScrollableScrollPhysics(),
        child: Padding(
          padding: EdgeInsets.only(bottom: 32.h),
          child: Column(
            children: [
              SizedBox(height: 24.h),
              Card(
                color: Colors.white,
                margin: EdgeInsets.symmetric(horizontal: 24.w),
                elevation: 4,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8.r),
                ),
                child: Padding(
                  padding: EdgeInsets.all(24.w),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      RichText(
                        text: TextSpan(
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            fontSize: 24.sp,
                          ),
                          children: const [
                            TextSpan(
                              text: ' L',
                              style: TextStyle(
                                color: Color.fromARGB(230, 2, 47, 123),
                              ),
                            ),
                            TextSpan(
                              text: 'O',
                              style: TextStyle(
                                color: Color.fromARGB(255, 230, 10, 144),
                              ),
                            ),
                            TextSpan(
                              text: 'GIN',
                              style: TextStyle(
                                color: Color.fromARGB(230, 2, 47, 123),
                              ),
                            ),
                          ],
                        ),
                      ),
                      SizedBox(height: 20.h),
                      TextField(
                        controller: idController,
                        cursorColor: Colors.black,
                        decoration: InputDecoration(
                          labelText: "학번/사번",
                          border: const OutlineInputBorder(),
                          enabledBorder: OutlineInputBorder(
                            borderSide: BorderSide(
                              color: Colors.grey.shade400,
                              width: 1.0,
                            ),
                          ),
                          focusedBorder: const OutlineInputBorder(
                            borderSide: BorderSide(
                              color: Colors.black,
                              width: 1.2,
                            ),
                          ),
                          prefixIcon: const Icon(Icons.person_outlined),
                          floatingLabelStyle: const TextStyle(
                            color: Colors.black,
                          ),
                        ),
                      ),
                      SizedBox(height: 12.h),
                      TextField(
                        controller: pwController,
                        obscureText: _obscurePassword,
                        cursorColor: Colors.black,
                        decoration: InputDecoration(
                          labelText: "비밀번호",
                          border: const OutlineInputBorder(),
                          enabledBorder: OutlineInputBorder(
                            borderSide: BorderSide(
                              color: Colors.grey.shade400,
                              width: 1.0,
                            ),
                          ),
                          focusedBorder: const OutlineInputBorder(
                            borderSide: BorderSide(
                              color: Colors.black,
                              width: 1.2,
                            ),
                          ),
                          prefixIcon: const Icon(Icons.lock_outlined),
                          suffixIcon: IconButton(
                            icon: Icon(
                              _obscurePassword
                                  ? Icons.visibility_off
                                  : Icons.visibility,
                            ),
                            onPressed: () {
                              setState(() {
                                _obscurePassword = !_obscurePassword;
                              });
                            },
                          ),
                          floatingLabelStyle: const TextStyle(
                            color: Colors.black,
                          ),
                        ),
                      ),
                      SizedBox(height: 15.h),
                      if (message.isNotEmpty)
                        Padding(
                          padding: EdgeInsets.only(bottom: 12.h, left: 4.w),
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Text(
                              message,
                              style: TextStyle(
                                color: Colors.red,
                                fontSize: 14.sp,
                                fontWeight: FontWeight.w500,
                              ),
                              textAlign: TextAlign.left,
                            ),
                          ),
                        ),
                      ElevatedButton(
                        onPressed: _isLoading ? null : login,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color.fromARGB(
                            230,
                            2,
                            47,
                            123,
                          ),
                          minimumSize: Size.fromHeight(48.h),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(5.r),
                          ),
                          elevation: 4,
                        ),
                        child: Padding(
                          padding: EdgeInsets.symmetric(
                            vertical: 12.h,
                            horizontal: 24.w,
                          ),
                          child: Text(
                            "로그인",
                            style: TextStyle(
                              fontSize: 16.sp,
                              color: Colors.white,
                            ),
                          ),
                        ),
                      ),
                      SizedBox(height: 15.h),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: [
                          GestureDetector(
                            onTap: () {
                              launchUrl(
                                Uri.parse(
                                  'https://newportal.kbu.ac.kr/por/pg?pgmId=P002423',
                                ),
                              );
                            },
                            child: Container(
                              decoration: const BoxDecoration(
                                border: Border(
                                  bottom: BorderSide(
                                    color: Colors.grey,
                                    width: 0.6,
                                  ),
                                ),
                              ),
                              child: Text(
                                '아이디 찾기',
                                style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  color: Colors.grey,
                                  fontSize: 13.sp,
                                ),
                              ),
                            ),
                          ),
                          SizedBox(width: 16.w),
                          GestureDetector(
                            onTap: () {
                              launchUrl(
                                Uri.parse(
                                  'https://newportal.kbu.ac.kr/por/pg?pgmId=P006740',
                                ),
                              );
                            },
                            child: Container(
                              decoration: const BoxDecoration(
                                border: Border(
                                  bottom: BorderSide(
                                    color: Colors.grey,
                                    width: 0.6,
                                  ),
                                ),
                              ),
                              child: Text(
                                '비밀번호 찾기',
                                style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  color: Colors.grey,
                                  fontSize: 13.sp,
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                      SizedBox(height: 18.h),
                      Container(
                        padding: EdgeInsets.all(16.w),
                        decoration: BoxDecoration(
                          color: Colors.grey[200],
                          borderRadius: BorderRadius.circular(8.r),
                        ),
                        child: Column(
                          children: [
                            Text(
                              '※ 초기 비밀번호\n생년월일(YYMMDD) + 12!',
                              textAlign: TextAlign.center,
                              style: TextStyle(
                                fontSize: 15.sp,
                                fontWeight: FontWeight.bold,
                                color: const Color.fromARGB(255, 230, 10, 144),
                              ),
                            ),
                            SizedBox(height: 8.h),
                            Padding(
                              padding: EdgeInsets.symmetric(horizontal: 32.w),
                              child: Text(
                                '포인트 결제 후 오류 발생 시\n'
                                '해당 연락처로 문의 바랍니다.\n'
                                '(포인트 충전은 처리에 다소 시간이 소요될 수 있음)',
                                textAlign: TextAlign.center,
                                style: TextStyle(
                                  fontSize: 14.sp,
                                  fontWeight: FontWeight.bold,
                                  color: const Color.fromARGB(230, 2, 47, 123),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
