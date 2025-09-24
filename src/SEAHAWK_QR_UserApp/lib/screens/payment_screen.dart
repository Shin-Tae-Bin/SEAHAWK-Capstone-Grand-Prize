// 이 파일은 사용자의 QR 코드 결제를 처리하는 메인 화면입니다.
// 서버로부터 사용자별 고유 QR 데이터를 받아와 60초의 유효기간을 가진 QR코드를 화면에 표시합니다.
// 사용자의 현재 보유 포인트를 함께 보여주며, QR 코드 유효시간이 만료되면 재발급을 유도합니다.
// UI는 티켓 형태의 디자인으로 구성되어 있으며, 포인트 거래 내역 화면으로 이동하는 기능을 포함합니다.

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import '../services/api_constants.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'dart:convert';
import 'dart:async';
import 'package:qr_flutter/qr_flutter.dart';
import './point_transaction_screen.dart';
import 'package:intl/intl.dart';
import 'package:shared_preferences/shared_preferences.dart';

class PaymentScreen extends StatefulWidget {
  final String userId;
  const PaymentScreen({super.key, required this.userId});

  @override
  State<PaymentScreen> createState() => _PaymentScreenState();
}

class _PaymentScreenState extends State<PaymentScreen> with WidgetsBindingObserver {
  int _userPoints = 0;
  String _qrImageUrl = '';
  bool _isLoading = false;
  DateTime? _qrGeneratedAt;
  int _qrRemainingSeconds = 0;
  Timer? _qrTimer;
  bool _showExpiredMessage = false;

  @override
  void initState() {
    super.initState();
    _loadSavedQrData();
    _refreshData();
    _fetchQrData();
    
    // 앱이 백그라운드로 갈 때와 포그라운드로 돌아올 때 감지
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    
    if (state == AppLifecycleState.paused) {
      // 앱이 백그라운드로 갈 때 타이머는 계속 동작하도록 함
      print('앱이 백그라운드로 이동');
    } else if (state == AppLifecycleState.resumed) {
      // 앱이 포그라운드로 돌아올 때 저장된 시간을 확인하고 타이머 업데이트
      _updateTimerFromSavedData();
    }
  }

  Future<void> _updateTimerFromSavedData() async {
    final prefs = await SharedPreferences.getInstance();
    final savedQrGeneratedAt = prefs.getInt('qr_generated_at_${widget.userId}');
    
    if (savedQrGeneratedAt != null) {
      final generatedAt = DateTime.fromMillisecondsSinceEpoch(savedQrGeneratedAt);
      final now = DateTime.now();
      final elapsedSeconds = now.difference(generatedAt).inSeconds;
      
      if (elapsedSeconds < 60) {
        setState(() {
          _qrRemainingSeconds = 60 - elapsedSeconds;
          _showExpiredMessage = false;
        });
      } else {
        setState(() {
          _qrRemainingSeconds = 0;
          _showExpiredMessage = true;
        });
        _qrTimer?.cancel();
      }
    }
  }

  Future<void> _loadSavedQrData() async {
    final prefs = await SharedPreferences.getInstance();
    final savedQrGeneratedAt = prefs.getInt('qr_generated_at_${widget.userId}');
    final savedQrImageUrl = prefs.getString('qr_image_url_${widget.userId}');
    
    if (savedQrGeneratedAt != null && savedQrImageUrl != null) {
      final generatedAt = DateTime.fromMillisecondsSinceEpoch(savedQrGeneratedAt);
      final now = DateTime.now();
      final elapsedSeconds = now.difference(generatedAt).inSeconds;
      
      if (elapsedSeconds < 60) {
        setState(() {
          _qrImageUrl = savedQrImageUrl;
          _qrGeneratedAt = generatedAt;
          _qrRemainingSeconds = 60 - elapsedSeconds;
          _showExpiredMessage = false;
        });
        _startQrTimer();
      }
    }
  }

  Future<void> _fetchQrData() async {
    try {
      final response = await http.get(
        Uri.parse('${ApiConstants.generatePaymentQr}?id=${widget.userId}'),
      );
      if (response.statusCode == 200 &&
          response.body.isNotEmpty &&
          !response.body.startsWith("fail")) {
        final qrData = response.body.trim();
        final qrImageUrl = '$qrData#${DateTime.now().millisecondsSinceEpoch}';
        final generatedAt = DateTime.now();
        
        // QR 데이터를 SharedPreferences에 저장
        final prefs = await SharedPreferences.getInstance();
        await prefs.setInt('qr_generated_at_${widget.userId}', generatedAt.millisecondsSinceEpoch);
        await prefs.setString('qr_image_url_${widget.userId}', qrImageUrl);
        
        setState(() {
          _qrImageUrl = qrImageUrl;
          _qrGeneratedAt = generatedAt;
          _qrRemainingSeconds = 60;
          _showExpiredMessage = false;
        });
        _qrTimer?.cancel();
        _startQrTimer();
      } else {
        print('QR 데이터 생성 실패 : ${response.body}');
      }
    } catch (e) {
      print('QR 요청 오류: $e');
    }
  }

  Future<void> _refreshData() async {
    await _fetchUserData();
  }

  Future<void> _fetchUserData() async {
    try {
      final response = await http.get(
        Uri.parse('${ApiConstants.userpoint}?userId=${widget.userId}'),
      );
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data['success'] == true) {
          setState(() {
            _userPoints = data['points'];
          });
        }
      }
    } catch (e) {
      print('💥 예외 발생: $e');
    }
  }

  void _startQrTimer() {
    _qrTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (_qrRemainingSeconds <= 0) {
        timer.cancel();
        setState(() {
          _showExpiredMessage = true;
        });
      } else {
        setState(() {
          _qrRemainingSeconds--;
        });
      }
    });
  }

  @override
  void dispose() {
    _qrTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    Future.microtask(() => _refreshData());

    const gold = Color.fromARGB(255, 255, 223, 0);
    final double boxTop = MediaQuery.of(context).size.height * 0.15;
    final double boxWidth = 310.w;
    final double boxLeft = MediaQuery.of(context).size.width / 2 - boxWidth / 2;
    const double holeRadius = 16.0;
    final double sideMargin = 40.w;

    return Scaffold(
      appBar: PreferredSize(
        preferredSize: Size.fromHeight(50.h),
        child: Material(elevation: 0, shadowColor: Colors.black),
      ),
      backgroundColor: const Color.fromARGB(0, 246, 246, 246),
      body:
          _isLoading
              ? const Center(child: CircularProgressIndicator(color: gold))
              : Stack(
                children: [
                  Positioned(
                    top: boxTop,
                    left: 0,
                    right: 0,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        Container(
                          width: boxWidth,
                          height: boxWidth,
                          margin: EdgeInsets.symmetric(horizontal: sideMargin),
                          child: ClipPath(
                            clipper: HoleClipper(),
                            child: Container(
                              decoration: BoxDecoration(
                                color: const Color.fromARGB(255, 219, 219, 219),
                                borderRadius: BorderRadius.circular(16.r),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.grey.withOpacity(0.18),
                                    blurRadius: 8,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  const Spacer(),
                                  Text(
                                    '내 포인트',
                                    style: TextStyle(
                                      fontSize: 16.sp,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.black,
                                    ),
                                  ),
                                  Text(
                                    '${_userPoints.toString().replaceAllMapped(RegExp(r'(\d)(?=(\d{3})+(?!\d))'), (m) => '${m[1]},')}P',
                                    style: TextStyle(
                                      fontSize: 28.sp,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.black,
                                    ),
                                  ),
                                  SizedBox(height: 24.h),
                                ],
                              ),
                            ),
                          ),
                        ),
                        Positioned(
                          child: IgnorePointer(
                            child: CustomPaint(
                              size: Size(boxWidth - 12.w, boxWidth - 12.w),
                              painter: HoleBorderPainter(
                                borderRadius: 14.r,
                                holeRadius: 12.0,
                              ),
                            ),
                          ),
                        ),
                        Positioned.fill(
                          child: IgnorePointer(
                            child: CustomPaint(
                              painter: DottedLinePainter(
                                margin: sideMargin,
                                holeRadius: holeRadius,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  Positioned(
                    top: boxTop + boxWidth * 0.65,
                    left: boxLeft,
                    width: boxWidth,
                    height: boxWidth * 0.35,
                    child: GestureDetector(
                      behavior: HitTestBehavior.opaque,
                      onTap: () {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder:
                                (context) => PointTransactionScreen(
                                  userId: widget.userId,
                                ),
                          ),
                        );
                      },
                      child: Container(),
                    ),
                  ),
                  Positioned(
                    top: boxTop + boxWidth + 10.h,
                    left: MediaQuery.of(context).size.width / 2 - 155.w,
                    right: MediaQuery.of(context).size.width / 2 - 155.w,
                    child: LayoutBuilder(
                      builder: (context, constraints) {
                        return Stack(
                          alignment: Alignment.center,
                          children: [
                            Container(
                              padding: EdgeInsets.symmetric(
                                horizontal: 16.w,
                                vertical: 14.h,
                              ),
                              decoration: BoxDecoration(
                                color: const Color.fromARGB(255, 219, 219, 219),
                                borderRadius: BorderRadius.circular(16.r),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.grey.withOpacity(0.18),
                                    blurRadius: 8,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Row(
                                    children: [
                                      Expanded(
                                        child: ClipRRect(
                                          borderRadius: BorderRadius.circular(
                                            8.r,
                                          ),
                                          child: ShaderMask(
                                            shaderCallback: (Rect bounds) {
                                              return const LinearGradient(
                                                colors: [
                                                  Color.fromARGB(
                                                    255,
                                                    196,
                                                    113,
                                                    237,
                                                  ),
                                                  Color.fromARGB(
                                                    255,
                                                    227,
                                                    0,
                                                    122,
                                                  ),
                                                ],
                                                begin: Alignment.centerLeft,
                                                end: Alignment.centerRight,
                                              ).createShader(bounds);
                                            },
                                            child: LinearProgressIndicator(
                                              value: _qrRemainingSeconds / 60,
                                              backgroundColor: Colors.black,
                                              valueColor:
                                                  const AlwaysStoppedAnimation<
                                                    Color
                                                  >(Colors.white),
                                              minHeight: 8.h,
                                            ),
                                          ),
                                        ),
                                      ),
                                      SizedBox(width: 14.w),
                                      GestureDetector(
                                        onTap: _fetchQrData,
                                        child: Icon(
                                          Icons.refresh,
                                          color: Colors.black,
                                          size: 24.sp,
                                        ),
                                      ),
                                    ],
                                  ),
                                  if (_showExpiredMessage)
                                    Padding(
                                      padding: EdgeInsets.only(
                                        top: 6.h,
                                        bottom: 4.h,
                                      ),
                                      child: Text(
                                        'QR 코드를 재갱신 해주세요.',
                                        style: TextStyle(
                                          color: Colors.red,
                                          fontSize: 13.sp,
                                          fontWeight: FontWeight.bold,
                                        ),
                                      ),
                                    ),
                                  Text(
                                    '남은시간 : $_qrRemainingSeconds초',
                                    style: TextStyle(
                                      fontSize: 14.sp,
                                      color: Colors.black,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            Positioned.fill(
                              child: IgnorePointer(
                                child: Container(
                                  margin: EdgeInsets.all(5.w),
                                  decoration: BoxDecoration(
                                    borderRadius: BorderRadius.circular(14.r),
                                    border: Border.all(
                                      color: Colors.white,
                                      width: 1.5,
                                    ),
                                  ),
                                ),
                              ),
                            ),
                          ],
                        );
                      },
                    ),
                  ),
                  Align(
                    alignment: Alignment.topCenter,
                    child: Padding(
                      padding: EdgeInsets.only(
                        top: MediaQuery.of(context).size.height * 0.04,
                      ),
                      child: Container(
                        padding: EdgeInsets.all(18.w),
                        decoration: BoxDecoration(
                          border: Border.all(
                            color: const Color.fromARGB(255, 180, 180, 180),
                            width: 2.w,
                          ),
                          borderRadius: BorderRadius.circular(16.r),
                          color: Colors.white,
                        ),
                        child:
                            _qrImageUrl.isNotEmpty && _qrGeneratedAt != null
                                ? QrImageView(
                                  data: _qrImageUrl,
                                  version: QrVersions.auto,
                                  size: 200.w,
                                  gapless: false,
                                )
                                : ElevatedButton(
                                  onPressed: _fetchQrData,
                                  child: Text('QR 불러오는중'),
                                ),
                      ),
                    ),
                  ),
                ],
              ),
    );
  }
}

class HoleClipper extends CustomClipper<Path> {
  @override
  Path getClip(Size size) {
    final path =
        Path()..addRRect(
          RRect.fromRectAndRadius(
            Rect.fromLTWH(0, 0, size.width, size.height),
            Radius.circular(20.r),
          ),
        );
    const holeRadius = 12.0;
    final centerY = size.height * 0.65;
    final leftHole =
        Path()..addOval(
          Rect.fromCircle(center: Offset(0, centerY), radius: holeRadius),
        );
    final rightHole =
        Path()..addOval(
          Rect.fromCircle(
            center: Offset(size.width, centerY),
            radius: holeRadius,
          ),
        );
    final withLeftHole = Path.combine(PathOperation.difference, path, leftHole);
    return Path.combine(PathOperation.difference, withLeftHole, rightHole);
  }

  @override
  bool shouldReclip(CustomClipper<Path> oldClipper) => false;
}

class HoleBorderPainter extends CustomPainter {
  final double borderRadius;
  final double holeRadius;

  HoleBorderPainter({required this.borderRadius, required this.holeRadius});

  @override
  void paint(Canvas canvas, Size size) {
    final paint =
        Paint()
          ..color = Colors.white
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.5;

    final rect = RRect.fromRectAndRadius(
      Rect.fromLTWH(0, 0, size.width, size.height),
      Radius.circular(borderRadius),
    );
    final path = Path()..addRRect(rect);
    final leftHole =
        Path()..addOval(
          Rect.fromCircle(
            center: Offset(0, size.height * 0.655),
            radius: holeRadius + 3.r,
          ),
        );
    final rightHole =
        Path()..addOval(
          Rect.fromCircle(
            center: Offset(size.width, size.height * 0.655),
            radius: holeRadius + 3.r,
          ),
        );
    final fullPath = Path.combine(PathOperation.difference, path, leftHole);
    final finalPath = Path.combine(
      PathOperation.difference,
      fullPath,
      rightHole,
    );
    canvas.drawPath(finalPath, paint);
  }

  @override
  bool shouldRepaint(CustomPainter oldDelegate) => false;
}

class DottedLinePainter extends CustomPainter {
  final double margin;
  final double holeRadius;

  DottedLinePainter({required this.margin, required this.holeRadius});

  @override
  void paint(Canvas canvas, Size size) {
    final paint =
        Paint()
          ..color = Colors.white
          ..strokeWidth = 1.5
          ..style = PaintingStyle.stroke;

    const dashWidth = 5.8;
    const dashSpace = 4.0;
    final y = size.height * 0.65;
    final startX = holeRadius + margin + 8.w;
    final endX = size.width - holeRadius - margin - 8.w;

    double x = startX;
    while (x < endX) {
      final dashEnd = (x + dashWidth < endX) ? x + dashWidth : endX;
      canvas.drawLine(Offset(x, y), Offset(dashEnd, y), paint);
      x += dashWidth + dashSpace;
    }
  }

  @override
  bool shouldRepaint(CustomPainter oldDelegate) => false;
}
