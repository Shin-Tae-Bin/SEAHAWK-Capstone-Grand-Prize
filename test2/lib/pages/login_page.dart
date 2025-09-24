// POS 시스템의 로그인 페이지입니다.
// 사용자는 식당을 선택하고 비밀번호를 입력하여 로그인합니다.
// 로그인 성공 시 결제 페이지(PaymentPage)로 이동합니다.

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'payment_page.dart';

class LoginPage extends StatefulWidget {
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final TextEditingController _passwordController = TextEditingController();
  bool _isPasswordVisible = false;
  bool _isLoading = false;
  String _selectedRestaurant = '아질리아';
  String _errorMessage = '';

  Future<void> _login() async {
    if (_passwordController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('비밀번호를 입력해주세요'), backgroundColor: Colors.red),
      );
      return; 
    }

    setState(() {
      _isLoading = true;
      _errorMessage = '';
    });

    try {
      final username =
          _selectedRestaurant == '피오니' ? 'pos_admin2' : 'pos_admin';

      final response = await http.post(
        Uri.parse('https://qr.pjhpjh.kr/pos_node/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'username': username,
          'password': _passwordController.text,
        }),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data['token'] != null) {
          final String menuName;
          final int price;
          if (_selectedRestaurant == '아질리아') {
            menuName = '아질리아 식권';
            price = 4800;
          } else {
            menuName = '피오니 식권';
            price = 5000;
          }

          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder:
                  (_) => PaymentPage(
                    token: data['token'],
                    restaurant: _selectedRestaurant,
                    menuName: menuName,
                    price: price,
                  ),
            ),
          );
        } else {
          throw Exception('API 응답에 토큰이 없습니다.');
        }
      } else {
        final errorData = jsonDecode(response.body);
        final errorMessage =
            errorData['message'] ?? '로그인에 실패했습니다. 비밀번호를 확인해주세요.';
        throw Exception(errorMessage);
      }
    } catch (e) {
      setState(() {
        _errorMessage = '비밀번호가 잘못되었습니다. 다시 확인해주세요.';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    return Scaffold(
      backgroundColor: Colors.white,
      body: SafeArea(
        child: Stack(
          children: [
            Align(
              alignment: Alignment.topCenter,
              child: Padding(
                padding: const EdgeInsets.only(top: 60.0),
                child: Image.asset('images/kbu_logo.png', height: 60),
              ),
            ),
            Center(
              child: SingleChildScrollView(
                child: Container(
                  constraints: BoxConstraints(maxWidth: screenWidth * 0.6),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(6),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withOpacity(0.1),
                        blurRadius: 15,
                        spreadRadius: 2,
                        offset: Offset(0, 5),
                      ),
                    ],
                  ),
                  child: Padding(
                    padding: EdgeInsets.all(24),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          ' 경복대학교 학식 POS 로그인',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w600,
                            color: Colors.black87,
                          ),
                        ),
                        SizedBox(height: 16),
                        Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.white,
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: Colors.grey[300]!),
                          ),
                          child: DropdownButtonHideUnderline(
                            child: DropdownButton<String>(
                              value: _selectedRestaurant,
                              isExpanded: true,
                              dropdownColor: Colors.white,
                              items: [
                                DropdownMenuItem(
                                  value: '아질리아',
                                  child: Text(
                                    '아질리아',
                                    style: TextStyle(
                                      fontSize: 14,
                                      color: Colors.black87,
                                    ),
                                  ),
                                ),
                                DropdownMenuItem(
                                  value: '피오니',
                                  child: Text(
                                    '피오니',
                                    style: TextStyle(
                                      fontSize: 14,
                                      color: Colors.black87,
                                    ),
                                  ),
                                ),
                              ],
                              onChanged: (value) {
                                if (value != null) {
                                  setState(() {
                                    _selectedRestaurant = value;
                                  });
                                }
                              },
                            ),
                          ),
                        ),
                        SizedBox(height: 16),
                        TextField(
                          controller: _passwordController,
                          obscureText: !_isPasswordVisible,
                          style: TextStyle(color: Colors.black),
                          decoration: InputDecoration(
                            labelText: '비밀번호',
                            labelStyle: TextStyle(color: Colors.black),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(6),
                            ),
                            enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(6),
                              borderSide: BorderSide(color: Colors.grey[300]!),
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(6),
                              borderSide: BorderSide(
                                color: Colors.black,
                                width: 1.2,
                              ),
                            ),
                            suffixIcon: IconButton(
                              icon: Icon(
                                _isPasswordVisible
                                    ? Icons.visibility_off
                                    : Icons.visibility,
                                color: Colors.grey[600],
                              ),
                              onPressed: () {
                                setState(() {
                                  _isPasswordVisible = !_isPasswordVisible;
                                });
                              },
                            ),
                          ),
                        ),
                        if (_errorMessage.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(
                              top: 12.0,
                              bottom: 4.0,
                            ),
                            child: Center(
                              child: Text(
                                _errorMessage,
                                style: TextStyle(
                                  color: Colors.red,
                                  fontSize: 14,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                          ),
                        SizedBox(height: _errorMessage.isNotEmpty ? 12 : 24),
                        SizedBox(
                          width: double.infinity,
                          child: ElevatedButton(
                            onPressed: _isLoading ? null : _login,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color.fromARGB(
                                230,
                                2,
                                47,
                                123,
                              ),
                              foregroundColor: Colors.white,
                              elevation: 0,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(6),
                              ),
                              padding: EdgeInsets.symmetric(vertical: 12),
                            ),
                            child:
                                _isLoading
                                    ? SizedBox(
                                      width: 20,
                                      height: 20,
                                      child: CircularProgressIndicator(
                                        color: Colors.white,
                                        strokeWidth: 2,
                                      ),
                                    )
                                    : Text(
                                      '로그인',
                                      style: TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                          ),
                        ),
                      ],
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
