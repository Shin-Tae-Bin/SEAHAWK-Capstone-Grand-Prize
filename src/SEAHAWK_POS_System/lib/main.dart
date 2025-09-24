// 이 파일은 애플리케이션의 시작점입니다.
// 앱의 기본 테마, 라우팅 및 초기 화면을 설정합니다.
// LoginPage를 앱의 첫 화면으로 지정합니다.

import 'package:flutter/material.dart';
import 'pages/login_page.dart';

void main() => runApp(POSApp());

class POSApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '경복대 학식 POS',
      theme: ThemeData(
        primarySwatch: Colors.grey,
        fontFamily: 'Pretendard',
        scaffoldBackgroundColor: Colors.white,
      ),
      home: LoginPage(),
      debugShowCheckedModeBanner: false,
    );
  }
}
