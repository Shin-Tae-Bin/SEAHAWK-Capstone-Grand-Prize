import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'screens/login_screen.dart';
import 'screens/qr_screen.dart';
import 'screens/payment_screen.dart';
import 'screens/menu_screen.dart';
import 'screens/generate_payment_qr_for_payment_screen.dart';
import 'screens/point_transaction_screen.dart';
import 'package:intl/date_symbol_data_local.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

Future<Map<String, String?>> loadTokenAndUserInfo() async {
  final prefs = await SharedPreferences.getInstance();
  return {
    'token': prefs.getString('jwt_token'),
    'userId': prefs.getString('user_id'),
    'userName': prefs.getString('user_name'),
    'affiliation': prefs.getString('affiliation'),
    'profileImage': prefs.getString('profile_image'),
    'userType': prefs.getString('user_type'),
  };
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeDateFormatting('ko');
  final data = await loadTokenAndUserInfo();

  print("🔐 불러온 토큰: ${data['token']}");
  print("🧑‍ 사용자 ID: ${data['userId']}");
  print("📛 이름: ${data['userName']}");
  print("🏫 소속: ${data['affiliation']}");
  print("🖼 프로필 이미지: ${data['profileImage']}");
  print("👤 사용자 유형: ${data['userType']}");

  runApp(
    MyApp(
      token: data['token'],
      userId: data['userId'] ?? '',
      userName: data['userName'] ?? '',
      affiliation: data['affiliation'] ?? '',
      profileImage: data['profileImage'] ?? '',
      userType: data['userType'] ?? '',
    ),
  );
}

class MyApp extends StatelessWidget {
  final String? token;
  final String userId;
  final String userName;
  final String affiliation;
  final String profileImage;
  final String userType;

  const MyApp({
    Key? key,
    this.token,
    required this.userId,
    required this.userName,
    required this.affiliation,
    required this.profileImage,
    required this.userType,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: '경복대 출입증',
      theme: ThemeData(primarySwatch: Colors.blue),
      locale: Locale('ko'),
      supportedLocales: [Locale('ko')],
      localizationsDelegates: [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      routes: {
        '/login': (context) => const LoginScreen(),
        '/qr':
            (context) => QRScreen(
              userId: userId,
              userName: userName,
              affiliation: affiliation,
              profileImage: profileImage,
            ),
        '/payment': (context) => PaymentScreen(userId: userId),
        '/menu': (context) => WeeklyMenuScreen(),
        '/generate_payment_qr':
            (context) => GeneratePaymentQrForPaymentScreen(qrData: ''),
        '/point_transactions':
            (context) => PointTransactionScreen(userId: userId),
      },
      home:
          token != null
              ? QRScreen(
                userId: userId,
                userName: userName,
                affiliation: affiliation,
                profileImage: profileImage,
              )
              : const LoginScreen(),
    );
  }
}
