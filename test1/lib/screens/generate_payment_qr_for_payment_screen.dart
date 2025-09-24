// 이 파일은 결제용 QR 코드를 생성하고 화면에 표시하는 페이지입니다.
// 외부로부터 전달받은 `qrData`(결제 정보)를 사용하여 QR 코드를 렌더링합니다.

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

class GeneratePaymentQrForPaymentScreen extends StatelessWidget {
  final String qrData;

  const GeneratePaymentQrForPaymentScreen({Key? key, required this.qrData})
    : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('결제용 QR 코드')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            QrImageView(data: qrData, size: 250.0),
            SizedBox(height: 20),
            Text('POS 단말기에 스캔하세요.', style: TextStyle(fontSize: 16)),
          ],
        ),
      ),
    );
  }
}
