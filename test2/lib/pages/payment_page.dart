// 식권 결제를 처리하는 페이지입니다.
// 사용자는 수량을 조절하고 QR, 카드, 현금으로 결제할 수 있습니다.
// 결제 시도 후 성공 또는 실패 결과를 오버레이로 보여줍니다.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:math';

enum PaymentMethod { qr, card, cash }

class PaymentPage extends StatefulWidget {
  final String token;
  final String menuName;
  final int price;
  final String restaurant;

  PaymentPage({
    required this.token,
    required this.menuName,
    required this.price,
    required this.restaurant,
  });

  @override
  State<PaymentPage> createState() => _PaymentPageState();
}

class _PaymentPageState extends State<PaymentPage> {
  int _quantity = 1;
  bool _loading = false;
  bool _isQrProcessing = false;
  bool _isQrModeActive = false;

  bool _showResultOverlay = false;
  bool _isLastPaymentSuccessful = false;
  String _resultMessage = '';

  final TextEditingController _qrController = TextEditingController();
  final FocusNode _qrFocusNode = FocusNode();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _qrFocusNode.requestFocus();
    });
    _qrFocusNode.addListener(() {
      if (!_qrFocusNode.hasFocus) {
        _qrFocusNode.requestFocus();
      }
    });
  }

  @override
  void dispose() {
    _qrController.dispose();
    _qrFocusNode.dispose();
    super.dispose();
  }

  void _incrementQuantity() {
    if (_showResultOverlay) return;
    setState(() {
      if (_quantity < 20) _quantity++;
    });
  }

  void _decrementQuantity() {
    if (_showResultOverlay) return;
    setState(() {
      if (_quantity > 1) _quantity--;
    });
  }

  String _generateRandomCardNumber() {
    final random = Random();
    String cardNumber = (random.nextInt(5) + 1).toString();
    for (int i = 0; i < 15; i++) {
      cardNumber += random.nextInt(10).toString();
    }
    return cardNumber;
  }

  Future<void> _processQrPayment(String qrToken) async {
    if (_isQrProcessing) return;

    setState(() => _isQrProcessing = true);

    try {
      final response = await http.post(
        Uri.parse('https://qr.pjhpjh.kr/pos_node/pay'),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ${widget.token}',
        },
        body: jsonEncode({
          'qrToken': qrToken,
          'menuName': '${widget.restaurant} 식권 ${_quantity}개',
          'ticketCount': _quantity,
          'restaurant': widget.restaurant,
        }),
      );
      final responseData = jsonDecode(response.body);

      setState(() {
        _isQrModeActive = false;
        _isLastPaymentSuccessful = response.statusCode == 200;
        _resultMessage = responseData['message'] ?? '결제 결과를 확인할 수 없습니다.';
        _showResultOverlay = true;
      });
    } catch (e) {
      setState(() {
        _isQrModeActive = false;
        _isLastPaymentSuccessful = false;
        _resultMessage = '결제 처리 중 오류가 발생했습니다.';
        _showResultOverlay = true;
      });
    }
  }

  Future<void> _onPaymentPressed(PaymentMethod method) async {
    if (_loading || _isQrProcessing || _showResultOverlay) return;

    if (method == PaymentMethod.qr) {
      setState(() => _isQrModeActive = true);
      _qrFocusNode.requestFocus();
      return;
    }

    setState(() {
      _isQrModeActive = false;
      _loading = true;
    });

    try {
      String? cardNumber;
      if (method == PaymentMethod.card) {
        cardNumber = _generateRandomCardNumber();
      }

      final totalPrice = widget.price * _quantity;
      final response = await http.post(
        Uri.parse('https://qr.pjhpjh.kr/pos_node/manual_pay'),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ${widget.token}',
        },
        body: jsonEncode({
          'menuName': '${widget.restaurant} 식권 ${_quantity}개',
          'amount': totalPrice,
          'method': method.name,
          'cardNumber': cardNumber,
          'restaurant': widget.restaurant,
        }),
      );

      final data = jsonDecode(response.body);
      String serverMessage = data['message'] ?? '결제 완료';
      String displayMessage;

      if (serverMessage.contains('CARD')) {
        displayMessage = serverMessage.replaceFirst('CARD', '카드');
      } else if (serverMessage.contains('CASH')) {
        displayMessage = serverMessage.replaceFirst('CASH', '현금');
      } else {
        displayMessage = serverMessage;
      }

      setState(() {
        _isLastPaymentSuccessful = response.statusCode == 200;
        _resultMessage = displayMessage;
        _showResultOverlay = true;
      });
    } catch (e) {
      setState(() {
        _isLastPaymentSuccessful = false;
        _resultMessage = '결제 처리 중 오류가 발생했습니다.';
        _showResultOverlay = true;
      });
    }
  }

  Widget _buildQrScanOverlay() {
    return Visibility(
      visible: _isQrModeActive,
      child: Container(
        color: Colors.black.withOpacity(0.6),
        child: Center(
          child: Container(
            padding: EdgeInsets.symmetric(horizontal: 40, vertical: 32),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.2),
                  spreadRadius: 2,
                  blurRadius: 10,
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (_isQrProcessing)
                  Padding(
                    padding: const EdgeInsets.all(20.0),
                    child: CircularProgressIndicator(strokeWidth: 5),
                  )
                else
                  Icon(
                    Icons.qr_code_scanner_rounded,
                    size: 80,
                    color: Color(0xFF0969DA),
                  ),
                SizedBox(height: 24),
                Text(
                  _isQrProcessing ? '결제 처리 중입니다...' : 'QR 코드를 스캔해주세요...',
                  style: TextStyle(
                    fontSize: 22,
                    fontWeight: FontWeight.w600,
                    color: Colors.black87,
                  ),
                ),
                SizedBox(height: 32),
                ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.red,
                    foregroundColor: Colors.white,
                    padding: EdgeInsets.symmetric(horizontal: 40, vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: () => setState(() => _isQrModeActive = false),
                  child: Text(
                    '취소',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildResultOverlay() {
    final bool isSuccess = _isLastPaymentSuccessful;
    return Visibility(
      visible: _showResultOverlay,
      child: Container(
        color: Colors.black.withOpacity(0.6),
        child: Center(
          child: Container(
            padding: EdgeInsets.symmetric(horizontal: 40, vertical: 32),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.2),
                  spreadRadius: 2,
                  blurRadius: 10,
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  isSuccess
                      ? Icons.check_circle_outline_rounded
                      : Icons.error_outline_rounded,
                  size: 80,
                  color: isSuccess ? Colors.green[600] : Colors.red[600],
                ),
                SizedBox(height: 24),
                Text(
                  _resultMessage,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w600,
                    color: Colors.black87,
                  ),
                ),
                SizedBox(height: 32),
                ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor:
                        isSuccess
                            ? Color.fromARGB(255, 0, 94, 255)
                            : Colors.grey[700],
                    foregroundColor: Colors.white,
                    padding: EdgeInsets.symmetric(horizontal: 50, vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: () {
                    setState(() {
                      _showResultOverlay = false;
                      _loading = false;
                      _isQrProcessing = false;
                      _quantity = 1;
                      _resultMessage = '';
                      _qrController.clear();
                      _qrFocusNode.requestFocus();
                    });
                  },
                  child: Text(
                    '확인',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final totalPrice = widget.price * _quantity;
    final Color primaryColor = Color.fromARGB(255, 0, 94, 255);

    return Scaffold(
      backgroundColor: Colors.white,
      appBar: AppBar(
        backgroundColor: Colors.white,
        shadowColor: Colors.grey[200],
        centerTitle: true,
        title: Text(
          '${widget.restaurant}',
          style: TextStyle(
            color: Colors.black87,
            fontWeight: FontWeight.w600,
            fontSize: 34,
          ),
        ),
        iconTheme: IconThemeData(color: Colors.black87),
      ),
      body: Stack(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              children: [
                Expanded(
                  flex: 5,
                  child: InkWell(
                    onTap: _incrementQuantity,
                    child: Container(
                      width: double.infinity,
                      padding: EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        border: Border.all(color: Colors.grey.shade300),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Container(
                            padding: EdgeInsets.all(24),
                            decoration: BoxDecoration(
                              color: Colors.grey[100],
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Icon(
                              Icons.receipt_long_outlined,
                              size: 140,
                              color: Colors.grey.shade600,
                            ),
                          ),
                          SizedBox(height: 24),
                          Text(
                            widget.menuName,
                            style: TextStyle(
                              fontSize: 54,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 8),
                          Text(
                            '${widget.price.toString().replaceAllMapped(RegExp(r'\B(?=(\d{3})+(?!\d))'), (match) => ',')}원 / 1개',
                            style: TextStyle(
                              fontSize: 44,
                              color: Colors.grey.shade700,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                SizedBox(height: 14),
                Expanded(
                  flex: 3,
                  child: Row(
                    children: [
                      Expanded(
                        flex: 2,
                        child: Container(
                          decoration: BoxDecoration(
                            border: Border.all(color: Colors.grey.shade300),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: ClipRRect(
                            borderRadius: BorderRadius.circular(8),
                            child: Column(
                              children: [
                                Expanded(
                                  flex: 3,
                                  child: Row(
                                    children: [
                                      Expanded(
                                        flex: 1,
                                        child: InkWell(
                                          onTap: _decrementQuantity,
                                          child: Center(
                                            child: Icon(
                                              Icons.remove_circle,
                                              size: 70,
                                              color: Colors.grey.shade500,
                                            ),
                                          ),
                                        ),
                                      ),
                                      Expanded(
                                        flex: 1,
                                        child: Center(
                                          child: Text(
                                            '$_quantity',
                                            style: TextStyle(
                                              fontSize: 120,
                                              fontWeight: FontWeight.bold,
                                              color: Colors.black,
                                            ),
                                          ),
                                        ),
                                      ),
                                      Expanded(
                                        flex: 1,
                                        child: InkWell(
                                          onTap: _incrementQuantity,
                                          child: Center(
                                            child: Icon(
                                              Icons.add_circle,
                                              size: 70,
                                              color: Colors.grey.shade500,
                                            ),
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                                Divider(
                                  thickness: 1,
                                  height: 1,
                                  color: Colors.grey.shade300,
                                ),
                                Expanded(
                                  flex: 2,
                                  child: Row(
                                    children: [
                                      Expanded(
                                        flex: 4,
                                        child: Container(
                                          color: Colors.white,
                                          child: Padding(
                                            padding: const EdgeInsets.fromLTRB(
                                              24.0,
                                              0,
                                              32.0,
                                              0,
                                            ),
                                            child: Row(
                                              crossAxisAlignment:
                                                  CrossAxisAlignment.center,
                                              children: [
                                                Text(
                                                  '총 결제금액',
                                                  style: TextStyle(
                                                    fontSize: 18,
                                                    color: Colors.grey.shade700,
                                                    fontWeight: FontWeight.w600,
                                                  ),
                                                ),
                                                Spacer(),
                                                Text(
                                                  '${totalPrice.toString().replaceAllMapped(RegExp(r'\B(?=(\d{3})+(?!\d))'), (match) => ',')}원',
                                                  style: TextStyle(
                                                    fontSize: 44,
                                                    fontWeight: FontWeight.bold,
                                                  ),
                                                ),
                                              ],
                                            ),
                                          ),
                                        ),
                                      ),
                                      VerticalDivider(
                                        thickness: 1,
                                        width: 1,
                                        color: Colors.grey.shade300,
                                        indent: 16,
                                        endIndent: 16,
                                      ),
                                      Expanded(
                                        flex: 2,
                                        child: InkWell(
                                          onTap: () {
                                            if (_showResultOverlay) return;
                                            setState(() {
                                              _quantity = 1;
                                              _isQrModeActive = false;
                                            });
                                          },
                                          child: Container(
                                            width: double.infinity,
                                            height: double.infinity,
                                            color: Colors.red,
                                            child: Center(
                                              child: Text(
                                                '취소하기',
                                                style: TextStyle(
                                                  fontSize: 28,
                                                  fontWeight: FontWeight.bold,
                                                  color: Colors.white,
                                                ),
                                              ),
                                            ),
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
                      ),
                      SizedBox(width: 16),
                      Expanded(
                        flex: 1,
                        child: Column(
                          children:
                              PaymentMethod.values.expand((method) {
                                final bool isLastButton =
                                    method == PaymentMethod.values.last;
                                return [
                                  Expanded(
                                    child: ElevatedButton(
                                      onPressed:
                                          () => _onPaymentPressed(method),
                                      style: ElevatedButton.styleFrom(
                                        backgroundColor: primaryColor,
                                        foregroundColor: Colors.white,
                                        shape: RoundedRectangleBorder(
                                          borderRadius: BorderRadius.circular(
                                            12,
                                          ),
                                        ),
                                        minimumSize: Size(double.infinity, 0),
                                      ),
                                      child: Column(
                                        mainAxisAlignment:
                                            MainAxisAlignment.center,
                                        children: [
                                          Icon(
                                            _getPaymentMethodIcon(method),
                                            size: 60,
                                          ),
                                          SizedBox(height: 8),
                                          Text(
                                            _getPaymentMethodName(method),
                                            style: TextStyle(
                                              fontSize: 32,
                                              fontWeight: FontWeight.bold,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                                  ),
                                  if (!isLastButton) SizedBox(height: 8.0),
                                ];
                              }).toList(),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          SizedBox(
            width: 0,
            height: 0,
            child: TextField(
              controller: _qrController,
              focusNode: _qrFocusNode,
              autofocus: true,
              onSubmitted: (value) {
                if (_isQrModeActive && value.trim().isNotEmpty) {
                  _processQrPayment(value.trim());
                } else {
                  _qrController.clear();
                  _qrFocusNode.requestFocus();
                }
              },
            ),
          ),
          _buildQrScanOverlay(),
          _buildResultOverlay(),
        ],
      ),
    );
  }

  String _getPaymentMethodName(PaymentMethod method) {
    switch (method) {
      case PaymentMethod.qr:
        return 'QR 결제';
      case PaymentMethod.card:
        return '카드 결제';
      case PaymentMethod.cash:
        return '현금 결제';
    }
  }

  IconData _getPaymentMethodIcon(PaymentMethod method) {
    switch (method) {
      case PaymentMethod.qr:
        return Icons.qr_code_scanner_rounded;
      case PaymentMethod.card:
        return Icons.credit_card;
      case PaymentMethod.cash:
        return Icons.payments_rounded;
    }
  }
}
