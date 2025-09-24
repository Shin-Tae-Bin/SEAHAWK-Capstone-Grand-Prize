// 이 파일은 주간 식단표를 보여주는 페이지입니다.
// WebView를 사용하여 경복대학교의 공식 식단표 웹페이지를 로드합니다.
// 사용자는 이 화면을 통해 별도의 브라우저 앱 없이 주간 식단을 확인할 수 있습니다.

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

class WeeklyMenuScreen extends StatefulWidget {
  @override
  _WeeklyMenuScreenState createState() => _WeeklyMenuScreenState();
}

class _WeeklyMenuScreenState extends State<WeeklyMenuScreen> {
  late WebViewController _controller;

  @override
  void initState() {
    super.initState();
    _controller =
        WebViewController()
          ..setJavaScriptMode(JavaScriptMode.unrestricted)
          ..setNavigationDelegate(
            NavigationDelegate(
              onPageStarted: (String url) {
                print("페이지 로딩 시작 : $url");
              },
              onPageFinished: (String url) {
                print("페이지 로딩 완료 : $url");
              },
              onProgress: (int progress) {
                print("로딩 진행률 : $progress%");
              },
            ),
          )
          ..loadRequest(
            Uri.parse(
              'https://www.kbu.ac.kr/kor/CMS/DietMenuMgr/list.do?mCode=MN203',
            ),
          );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [Expanded(child: WebViewWidget(controller: _controller))],
      ),
      resizeToAvoidBottomInset: true,
    );
  }
}
