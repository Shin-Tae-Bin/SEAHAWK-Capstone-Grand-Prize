// 이 파일은 사용자의 포인트를 환불하는 페이지입니다.
// 사용자가 환불할 금액을 입력하고 '환불 요청' 버튼을 누르면,
// 확인 팝업을 거쳐 서버 API와 통신하여 포인트를 환불 처리합니다.
// 입력값이 유효하지 않거나 API 통신에 실패할 경우, 화면 중앙에 에러 메시지를 오버레이로 표시합니다.

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import '../services/api_constants.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'package:intl/intl.dart';
import 'package:flutter/services.dart';

class ChargeScreen extends StatefulWidget {
  final String userId;
  const ChargeScreen({super.key, required this.userId});

  @override
  State<ChargeScreen> createState() => _ChargeScreenState();
}

class _ChargeScreenState extends State<ChargeScreen> {
  final TextEditingController _amountController = TextEditingController();
  bool _loading = false;
  bool _showErrorOverlay = false;
  String _errorMessage = '';

  Future<void> _startFakeRefund() async {
    FocusScopeNode currentFocus = FocusScope.of(context);
    if (!currentFocus.hasPrimaryFocus && currentFocus.focusedChild != null) {
      currentFocus.focusedChild!.unfocus();
    }
    FocusScope.of(context).unfocus();
    SystemChannels.textInput.invokeMethod('TextInput.hide');
    await Future.delayed(const Duration(milliseconds: 150));

    final amountText = _amountController.text.trim();
    final amount = int.tryParse(amountText);

    if (amount == null || amount <= 0) {
      setState(() {
        _errorMessage = '올바른 금액을 입력하세요.';
        _showErrorOverlay = true;
      });
      return;
    }

    final formatter = NumberFormat('#,###');
    final formattedAmount = formatter.format(amount);

    final confirmed = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            backgroundColor: Colors.white,
            title: const Text('가상 충전 확인'),
            content: Text('$formattedAmount원을 충전하시겠습니까?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(context).pop(false),
                child: const Text(
                  '취소',
                  style: TextStyle(
                    color: Colors.red,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.blue[100],
                  foregroundColor: Colors.black,
                ),
                onPressed: () => Navigator.of(context).pop(true),
                child: const Text('충전하기'),
              ),
            ],
          ),
    );

    if (confirmed == true) {
      await _charge();
    }
  }

  Future<void> _charge() async {
    final amountText = _amountController.text.trim();
    final amount = int.tryParse(amountText);

    if (amount == null || amount <= 0) {
      setState(() {
        _errorMessage = '올바른 금액을 입력하세요.';
        _showErrorOverlay = true;
      });
      return;
    }

    setState(() => _loading = true);

    try {
      final response = await http.post(
        Uri.parse(ApiConstants.addPoints),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'userId': widget.userId,
          'amount': amount.toString(),
          'paymentMethod': 'bankAPI',
        },
      );

      if (!mounted) return;

      setState(() => _loading = false);

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data['success'] == true) {
          setState(() {
            _errorMessage = '충전이 완료되었습니다.';
            _showErrorOverlay = true;
          });
          return;
        }
      }

      setState(() {
        _errorMessage = '충전에 실패했습니다.';
        _showErrorOverlay = true;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _errorMessage = '오류 발생: $e';
        _showErrorOverlay = true;
      });
    }
  }

  Widget _buildErrorOverlay() {
    return Visibility(
      visible: _showErrorOverlay,
      child: Container(
        color: Colors.black.withOpacity(0.6),
        child: Center(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 32),
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
                  _errorMessage.contains('완료')
                      ? Icons.check_circle_outline
                      : Icons.error_outline_rounded,
                  size: 80,
                  color:
                      _errorMessage.contains('완료')
                          ? Colors.green[600]
                          : Colors.red[600],
                ),
                const SizedBox(height: 24),
                Text(
                  _errorMessage,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w600,
                    color: Colors.black87,
                  ),
                ),
                const SizedBox(height: 32),
                ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.grey[700],
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 50,
                      vertical: 16,
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: () {
                    if (_errorMessage == '올바른 금액을 입력하세요.') {
                      setState(() {
                        _showErrorOverlay = false;
                        _errorMessage = '';
                      });
                    } else {
                      Navigator.pop(context, true);
                    }
                  },
                  child: const Text(
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
    return Scaffold(
      backgroundColor: Colors.white,
      appBar: PreferredSize(
        preferredSize: Size.fromHeight(82.h),
        child: Material(
          child: AppBar(
            backgroundColor: Colors.white,
            toolbarHeight: 82,
            title: const Text('포인트 충전', style: TextStyle(color: Colors.black)),
            centerTitle: true,
            iconTheme: const IconThemeData(color: Colors.black),
            automaticallyImplyLeading: true,
            elevation: 0,
          ),
        ),
      ),
      body: Stack(
        children: [
          Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('충전할 금액을 입력하세요.', style: TextStyle(fontSize: 16)),
                const SizedBox(height: 16),
                TextField(
                  controller: _amountController,
                  keyboardType: TextInputType.number,
                  onEditingComplete: () {
                    FocusScope.of(context).unfocus();
                  },
                  cursorColor: Colors.black,
                  decoration: InputDecoration(
                    labelText: '금액 (원)',
                    border: const OutlineInputBorder(),
                    enabledBorder: OutlineInputBorder(
                      borderSide: BorderSide(
                        color: Colors.grey.shade400,
                        width: 1.0,
                      ),
                    ),
                    focusedBorder: const OutlineInputBorder(
                      borderSide: BorderSide(color: Colors.black, width: 1.2),
                    ),
                    floatingLabelStyle: const TextStyle(color: Colors.black),
                  ),
                ),
                const SizedBox(height: 24),
                Center(
                  child: ElevatedButton(
                    onPressed: _loading ? null : _startFakeRefund,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blue[100],
                      foregroundColor: Colors.black,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 40,
                        vertical: 14,
                      ),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                    child:
                        _loading
                            ? const SizedBox(
                              height: 20,
                              width: 20,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                            : const Text('충전 요청'),
                  ),
                ),
              ],
            ),
          ),
          _buildErrorOverlay(),
        ],
      ),
    );
  }
}
