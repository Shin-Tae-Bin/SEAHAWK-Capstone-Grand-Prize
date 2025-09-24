import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import '../services/api_constants.dart';
import 'payment_screen.dart';
import 'menu_screen.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'package:shared_preferences/shared_preferences.dart';

class QRScreen extends StatefulWidget {
  final String userId;
  final String userName;
  final String affiliation;
  final String profileImage;

  const QRScreen({
    Key? key,
    required this.userId,
    required this.userName,
    required this.affiliation,
    required this.profileImage,
  }) : super(key: key);

  @override
  State<QRScreen> createState() => _QRScreenState();
}

class _QRScreenState extends State<QRScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  String _qrData = '';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _tabController.addListener(() {
      setState(() {});
    });
    _fetchQRData();
  }

  void _fetchQRData() async {
    try {
      final response = await http.get(
        Uri.parse('${ApiConstants.qrGenerate}?id=${widget.userId}&raw=true'),
      );
      if (response.statusCode == 200) {
        setState(() {
          _qrData = response.body.trim();
        });
      } else {
        print("서버 오류: ${response.statusCode}");
      }
    } catch (e) {
      print("QR 가져오기 실패: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    ScreenUtil.init(context, designSize: const Size(390, 844));

    return WillPopScope(
      onWillPop: () async => false,
      child: Scaffold(
        backgroundColor: const Color.fromARGB(250, 255, 255, 255),
        appBar: PreferredSize(
          preferredSize: Size.fromHeight(82.h),
          child: Material(
            elevation: 0.15,
            shadowColor: Colors.grey,
            child: AppBar(
              backgroundColor: Colors.white,
              toolbarHeight: 82.h,
              title: Image.asset(
                'images/kbu_logo.png', 
                height: 50.h,
                fit: BoxFit.contain,
              ),
              centerTitle: true,
              iconTheme: const IconThemeData(color: Colors.black),
              automaticallyImplyLeading: false,
              actions: [
                IconButton(
                  icon: const Icon(Icons.logout),
                  onPressed: () async {
                    final prefs = await SharedPreferences.getInstance();
                    await prefs.remove('jwt_token');
                    await prefs.remove('user_id');
                    await prefs.remove('user_name');
                    await prefs.remove('user_type');
                    await prefs.remove('profile_image');
                    await prefs.remove('affiliation');
                    
                    if (!mounted) return;
                    Navigator.pushNamedAndRemoveUntil(context, '/login', (route) => false);
                  },
                ),
              ],
            ),
          ),
        ),
        body: Stack(
          children: [
            Positioned.fill(
              child: TabBarView(
                controller: _tabController,
                physics: const NeverScrollableScrollPhysics(),
                children: [
                  SingleChildScrollView(
                    padding: EdgeInsets.only(top: 100.h, bottom: 80.h),
                    child: Stack(
                      clipBehavior: Clip.none,
                      alignment: Alignment.topCenter,
                      children: [
                        Positioned(
                          top: -80.h,
                          child: Image.asset(
                            'images/bbogi_logo.png',  
                            width: 260.w,
                            height: 160.h,
                            fit: BoxFit.contain,
                          ),
                        ),
                        Align(
                          alignment: Alignment.center,
                          child: Container(
                            width: 312.w,
                            decoration: BoxDecoration(
                              color: const Color.fromARGB(255, 10, 80, 180),
                              borderRadius: BorderRadius.circular(14.r),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.grey.withOpacity(0.5),
                                  spreadRadius: 4,
                                  blurRadius: 8,
                                  offset: const Offset(0, 3),
                                ),
                              ],
                            ),
                            child: Column(
                              children: [
                                SizedBox(height: 12.h),
                                Center(
                                  child: Text(
                                    '출입증',
                                    style: TextStyle(
                                      fontSize: 24.sp,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.white,
                                    ),
                                  ),
                                ),
                                SizedBox(height: 10.h),
                                Container(
                                  width: 351.w,
                                  padding: EdgeInsets.symmetric(vertical: 6.h, horizontal: 24.w),
                                  decoration: const BoxDecoration(color: Colors.white),
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.center,
                                    children: [
                                      Container(
                                        width: 220.w,
                                        height: 220.w,
                                        decoration: BoxDecoration(
                                          color: Colors.white,
                                          borderRadius: BorderRadius.circular(6.r),
                                        ),
                                        child: _qrData.isNotEmpty
                                            ? ClipRRect(
                                                borderRadius: BorderRadius.circular(8.r),
                                                child: Image.network(
                                                  '${ApiConstants.qrImage}?data=${Uri.encodeComponent(_qrData)}',
                                                  fit: BoxFit.cover,
                                                  errorBuilder: (_, __, ___) => Text(
                                                    'QR 실패',
                                                    style: TextStyle(color: Colors.black, fontSize: 14.sp),
                                                  ),
                                                ),
                                              )
                                            : Center(
                                                child: CircularProgressIndicator(color: Colors.black),
                                              ),
                                      ),
                                      SizedBox(height: 12.h),
                                      Row(
                                        mainAxisAlignment: MainAxisAlignment.center,
                                        crossAxisAlignment: CrossAxisAlignment.start,
                                        children: [
                                          ClipRRect(
                                            borderRadius: BorderRadius.circular(2.r),
                                            child: Image.network(
                                              widget.profileImage,
                                              width: 95.w,
                                              height: 95.w,
                                              fit: BoxFit.cover,
                                              errorBuilder: (_, __, ___) => Container(
                                                width: 95.w,
                                                height: 95.w,
                                                color: Colors.grey[300],
                                                child: Icon(Icons.broken_image, size: 40.sp),
                                              ),
                                            ),
                                          ),
                                          SizedBox(width: 16.w),
                                          Column(
                                            crossAxisAlignment: CrossAxisAlignment.start,
                                            children: [
                                              Text(
                                                widget.userName,
                                                style: TextStyle(
                                                  fontSize: 20.sp,
                                                  fontWeight: FontWeight.bold,
                                                ),
                                              ),
                                              SizedBox(height: 4.h),
                                              Text(
                                                widget.userId,
                                                style: TextStyle(fontSize: 16.sp, color: Colors.black),
                                              ),
                                              SizedBox(height: 4.h),
                                              Text(
                                                widget.affiliation,
                                                style: TextStyle(fontSize: 16.sp, color: Colors.black),
                                              ),
                                              SizedBox(height: 44.h),
                                            ],
                                          ),
                                        ],
                                      ),
                                    ],
                                  ),
                                ),
                                SizedBox(height: 16.h),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  _KeepAlivePaymentScreen(userId: widget.userId),
                  WeeklyMenuScreen(),
                ],
              ),
            ),
            Positioned(
              left: 0,
              right: 0,
              bottom: 0,
              child: Container(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.only(
                    topLeft: Radius.circular(24.r),
                    topRight: Radius.circular(24.r),
                  ),
                  border: Border(
                    top: BorderSide(
                      color: Colors.grey.shade300,
                      width: 0.8,
                    ),
                  ),
                ),
                child: ClipRRect(
                  child: Container(
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.only(
                        topLeft: Radius.circular(24.r),
                        topRight: Radius.circular(24.r),
                      ),
                    ),
                    child: Theme(
                      data: Theme.of(context).copyWith(
                        splashFactory: NoSplash.splashFactory,
                        splashColor: Colors.transparent,
                        tabBarTheme: const TabBarThemeData(
                          overlayColor: WidgetStatePropertyAll(Colors.transparent),
                        ),
                      ),
                      child: TabBar(
                        controller: _tabController,
                        indicator: const BoxDecoration(),
                        labelColor: const Color.fromARGB(230, 2, 47, 123),
                        unselectedLabelColor: Colors.black54,
                        labelPadding: EdgeInsets.symmetric(vertical: 12.h),
                        tabs: List.generate(3, (index) {
                          bool selected = _tabController.index == index;
                          IconData iconData;
                          String text;
                          switch (index) {
                            case 0:
                              iconData = Icons.qr_code;
                              text = '출입증';
                              break;
                            case 1:
                              iconData = Icons.payment;
                              text = '식권 구매';
                              break;
                            case 2:
                              iconData = Icons.restaurant_menu;
                              text = '식단표';
                              break;
                            default:
                              iconData = Icons.help;
                              text = '알 수 없음';
                          }

                          return Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Transform.translate(
                                offset: Offset(0, -2.h),
                                child: Icon(
                                  iconData,
                                  size: index == 1 ? 30.sp : (selected ? 31.sp : 28.sp),
                                ),
                              ),
                              Text(
                                text,
                                style: TextStyle(
                                  fontSize: selected ? 17.sp : 13.sp,
                                  fontWeight: selected ? FontWeight.bold : FontWeight.normal,
                                ),
                              ),
                            ],
                          );
                        }),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _KeepAlivePaymentScreen extends StatefulWidget {
  final String userId;
  const _KeepAlivePaymentScreen({Key? key, required this.userId}) : super(key: key);

  @override
  State<_KeepAlivePaymentScreen> createState() => _KeepAlivePaymentScreenState();
}

class _KeepAlivePaymentScreenState extends State<_KeepAlivePaymentScreen>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  @override
  Widget build(BuildContext context) {
    super.build(context);
    FocusScope.of(context).unfocus();
    return PaymentScreen(userId: widget.userId);
  }
}