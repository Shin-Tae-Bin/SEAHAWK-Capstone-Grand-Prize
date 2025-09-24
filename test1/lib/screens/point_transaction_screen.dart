// 이 파일은 사용자의 포인트 거래 및 식권 사용 내역을 보여주는 페이지입니다.
// 서버로부터 포인트 충전/환불 내역과 식권 결제 내역을 모두 가져와 시간 순서대로 정렬하여 표시합니다.
// 사용자는 현재 보유 포인트를 확인할 수 있으며, '충전하기'와 '환불하기' 버튼을 통해 각 기능 페이지로 이동할 수 있습니다.
// 또한, 거래 유형별(전체, 충전, 환불, 식권) 및 월별로 내역을 필터링하여 조회하는 기능을 제공합니다.

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:intl/intl.dart';
import '../services/api_constants.dart';
import './charge_screen.dart';
import './refund_screen.dart';

class PointTransactionScreen extends StatefulWidget {
  final String userId;
  const PointTransactionScreen({super.key, required this.userId});

  @override
  State<PointTransactionScreen> createState() => _PointTransactionScreenState();
}

class _PointTransactionScreenState extends State<PointTransactionScreen> {
  List<dynamic> _transactions = [];
  int _userPoints = 0;
  String _selectedFilter = '전체';
  String _selectedMonthFilter = '전체';

  @override
  void initState() {
    super.initState();
    _fetchUserData(widget.userId);
    _fetchTransactions(widget.userId);
  }

  Future<void> _fetchUserData(String userId) async {
    try {
      final response = await http.get(
        Uri.parse('${ApiConstants.userpoint}?userId=$userId'),
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
      print('사용자 데이터 로딩 예외 발생: $e');
    }
  }

  Future<List<Map<String, dynamic>>> _fetchTicketTransactions(
    String userId,
  ) async {
    try {
      final response = await http.get(
        Uri.parse('${ApiConstants.userTicketUsageLog}?userId=$userId'),
      );
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data is List) {
          return data.map<Map<String, dynamic>>((tx) {
            String description;
            int cost = (tx['amount'] as num).abs().toInt();

            if (tx['menu_name'] != null &&
                (tx['menu_name'] as String).isNotEmpty) {
              description = tx['menu_name'];
            } else {
              if (cost == 4800) {
                description = '아질리아';
              } else if (cost == 5000) {
                description = '피오니';
              } else {
                description = '식권';
              }
            }

            return {
              'description': description,
              'amount': cost,
              'created_at': tx['payment_time'],
              'transaction_type': 'ticket_payment',
            };
          }).toList();
        } else {
          print('식권 내역 API 응답이 리스트가 아닙니다: $data');
          return [];
        }
      } else {
        print('식권 내역 API 오류: ${response.statusCode}');
        return [];
      }
    } catch (e) {
      print('식권 내역 API 예외 발생: $e');
      return [];
    }
  }

  Future<void> _fetchTransactions(String userId) async {
    List<dynamic> pointTxs = [];
    try {
      final response = await http.get(
        Uri.parse('${ApiConstants.getPointTransactions}?userId=$userId'),
      );
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data['success'] == true && data['transactions'] is List) {
          pointTxs = data['transactions'];
        }
      }
    } catch (e) {
      print('포인트 거래내역 로딩 예외 발생: $e');
    }

    final ticketTxs = await _fetchTicketTransactions(userId);

    setState(() {
      _transactions = [...pointTxs, ...ticketTxs];
      _transactions.sort((a, b) {
        final aDate = a['created_at'] ?? '';
        final bDate = b['created_at'] ?? '';
        return bDate.compareTo(aDate);
      });
    });
  }

  void _showFilterSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.white,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (BuildContext context) {
        return Padding(
          padding: const EdgeInsets.fromLTRB(16, 24, 16, 32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Center(
                child: Text(
                  '내역 선택',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
              const SizedBox(height: 16),
              ...['전체', '충전', '환불', '식권'].map((filter) {
                final isSelected = _selectedFilter == filter;
                return Material(
                  color: isSelected ? Colors.blue[100] : Colors.transparent,
                  borderRadius: BorderRadius.circular(10),
                  child: InkWell(
                    onTap: () {
                      setState(() {
                        _selectedFilter = filter;
                      });
                      Navigator.pop(context);
                    },
                    borderRadius: BorderRadius.circular(10),
                    child: Container(
                      width: double.infinity,
                      padding: const EdgeInsets.symmetric(
                        vertical: 16,
                        horizontal: 16,
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            filter,
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight:
                                  isSelected
                                      ? FontWeight.bold
                                      : FontWeight.normal,
                            ),
                          ),
                          if (isSelected) const Icon(Icons.check),
                        ],
                      ),
                    ),
                  ),
                );
              }).toList(),
            ],
          ),
        );
      },
    );
  }

  void _showMonthFilterSheet() {
    final now = DateTime.now();
    final months = [
      '전체',
      ...List.generate(12, (i) {
        final date = DateTime(now.year, now.month - i);
        return DateFormat('yyyy년 M월').format(date);
      }),
    ];
    final ScrollController scrollController = ScrollController();
    bool showTopGradient = false;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.white,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      constraints: BoxConstraints(
        maxHeight: MediaQuery.of(context).size.height * 0.6,
      ),
      builder: (BuildContext context) {
        return StatefulBuilder(
          builder: (context, setStateModal) {
            scrollController.addListener(() {
              if (scrollController.offset > 0 && !showTopGradient) {
                setStateModal(() => showTopGradient = true);
              } else if (scrollController.offset <= 0 && showTopGradient) {
                setStateModal(() => showTopGradient = false);
              }
            });
            return ClipRRect(
              borderRadius: const BorderRadius.vertical(
                top: Radius.circular(24),
              ),
              child: Stack(
                children: [
                  Padding(
                    padding: const EdgeInsets.only(bottom: 0),
                    child: SingleChildScrollView(
                      controller: scrollController,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const SizedBox(height: 80),
                          ...months.map((month) {
                            final isSelected = _selectedMonthFilter == month;
                            return Container(
                              margin: const EdgeInsets.symmetric(
                                horizontal: 16,
                              ),
                              decoration: BoxDecoration(
                                color:
                                    isSelected
                                        ? Colors.blue[100]
                                        : Colors.transparent,
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Material(
                                color: Colors.transparent,
                                borderRadius: BorderRadius.circular(10),
                                child: InkWell(
                                  onTap: () {
                                    setState(() {
                                      _selectedMonthFilter = month;
                                    });
                                    Navigator.pop(context);
                                  },
                                  borderRadius: BorderRadius.circular(10),
                                  child: Container(
                                    width: double.infinity,
                                    padding: const EdgeInsets.symmetric(
                                      vertical: 16,
                                      horizontal: 16,
                                    ),
                                    child: Row(
                                      mainAxisAlignment:
                                          MainAxisAlignment.spaceBetween,
                                      children: [
                                        Text(
                                          month,
                                          style: TextStyle(
                                            fontSize: 16,
                                            fontWeight:
                                                isSelected
                                                    ? FontWeight.bold
                                                    : FontWeight.normal,
                                            color: Colors.black,
                                          ),
                                        ),
                                        if (isSelected)
                                          const Icon(
                                            Icons.check,
                                            color: Colors.black,
                                            size: 20,
                                          ),
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                            );
                          }).toList(),
                          const SizedBox(height: 20),
                        ],
                      ),
                    ),
                  ),
                  if (showTopGradient)
                    Positioned(
                      top: 0,
                      left: 0,
                      right: 0,
                      child: Container(
                        height: 100,
                        decoration: const BoxDecoration(
                          gradient: LinearGradient(
                            begin: Alignment.topCenter,
                            end: Alignment.bottomCenter,
                            colors: [
                              Colors.white,
                              Colors.white,
                              Color.fromARGB(150, 255, 255, 255),
                              Color.fromARGB(0, 255, 255, 255),
                            ],
                            stops: [0.0, 0.6, 0.8, 1.0],
                          ),
                        ),
                      ),
                    ),
                  const Positioned(
                    top: 0,
                    left: 0,
                    right: 0,
                    child: SizedBox(
                      height: 80,
                      child: Center(
                        child: Text(
                          '기간 선택',
                          style: TextStyle(
                            fontSize: 22,
                            fontWeight: FontWeight.bold,
                            color: Colors.black,
                          ),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  List<dynamic> _getFilteredTransactions() {
    return _transactions.where((tx) {
      final transactionType = tx['transaction_type'];
      final matchesType =
          _selectedFilter == '전체' ||
          (_selectedFilter == '충전' && transactionType == 'charge') ||
          (_selectedFilter == '환불' && transactionType == 'refund') ||
          (_selectedFilter == '식권' && transactionType == 'ticket_payment');

      if (!matchesType) return false;
      if (_selectedMonthFilter == '전체') return true;

      final txDateStr = tx['created_at'] ?? '';
      if (txDateStr.isEmpty) return false;

      try {
        final txDate = DateTime.parse(txDateStr);
        final monthLabel = DateFormat('yyyy년 M월').format(txDate);
        return monthLabel == _selectedMonthFilter;
      } catch (_) {
        return false;
      }
    }).toList();
  }

  Map<String, List<dynamic>> _groupTransactionsByDate(
    List<dynamic> transactions,
  ) {
    Map<String, List<dynamic>> grouped = {};
    for (var tx in transactions) {
      final dateStr = tx['created_at'] ?? '';
      if (dateStr.isEmpty) continue;
      try {
        final date = DateTime.parse(dateStr);
        final dateLabel = DateFormat('yyyy-MM-dd').format(date);
        grouped.putIfAbsent(dateLabel, () => []).add(tx);
      } catch (_) {}
    }
    return grouped;
  }

  Widget _buildTransactionItem(Map<String, dynamic> tx) {
    final transactionType = tx['transaction_type'];
    final amount = (tx['amount'] as num?)?.toInt() ?? 0;
    final dateTimeStr = tx['created_at'] ?? '';

    String transactionLabel;
    IconData iconData;
    bool isDebit;
    Color iconColor;
    Color amountTextColor;

    if (transactionType == 'charge') {
      transactionLabel = tx['description'] ?? '포인트 충전';
      iconColor = Colors.blueAccent;
      amountTextColor = Colors.blueAccent;
      iconData = Icons.add_circle_outline;
      isDebit = false;
    } else if (transactionType == 'refund') {
      transactionLabel = tx['description'] ?? '포인트 환불';
      iconColor = Colors.redAccent;
      amountTextColor = Colors.redAccent;
      iconData = Icons.remove_circle_outline;
      isDebit = true;
    } else if (transactionType == 'ticket_payment') {
      transactionLabel = '식권 결제';
      iconColor = Colors.redAccent;
      amountTextColor = Colors.redAccent;
      iconData = Icons.confirmation_number_outlined;
      isDebit = true;
    } else {
      transactionLabel = tx['description'] ?? '기타 거래';
      iconColor = Colors.grey;
      amountTextColor = Colors.grey;
      iconData = Icons.help_outline;
      isDebit = true;
    }

    String formattedTime = '';
    if (dateTimeStr.isNotEmpty) {
      try {
        final parsedDate = DateTime.parse(dateTimeStr);
        formattedTime = DateFormat('HH:mm').format(parsedDate);
      } catch (_) {}
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Transform.translate(
            offset: const Offset(0, 8),
            child: Icon(iconData, color: iconColor, size: 34),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Flexible(
                      child: Text(
                        transactionLabel,
                        style: const TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    Text.rich(
                      TextSpan(
                        children: [
                          TextSpan(
                            text:
                                '${isDebit ? '-' : '+'}${NumberFormat('#,###').format(amount)}',
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: amountTextColor,
                            ),
                          ),
                          const TextSpan(
                            text: '원',
                            style: TextStyle(
                              fontSize: 17,
                              fontWeight: FontWeight.bold,
                              color: Colors.black,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                if (formattedTime.isNotEmpty)
                  Text(
                    formattedTime,
                    style: const TextStyle(fontSize: 12, color: Colors.grey),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 56),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final userId = widget.userId;
    final filteredTransactions = _getFilteredTransactions();
    final groupedTransactions = _groupTransactionsByDate(filteredTransactions);
    final sortedDates =
        groupedTransactions.keys.toList()..sort((a, b) => b.compareTo(a));
    final formatter = NumberFormat('#,###');

    return Scaffold(
      backgroundColor: Colors.white,
      appBar: AppBar(
        title: const Padding(
          padding: EdgeInsets.only(top: 8.0),
          child: Text('거래 내역'),
        ),
        backgroundColor: Colors.white,
        foregroundColor: Colors.black,
        elevation: 0,
        scrolledUnderElevation: 0,
      ),

      body: Column(
        children: [
          const SizedBox(height: 16),
          const Text(
            'My Point',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 8),
          Text(
            '${formatter.format(_userPoints)}P',
            style: const TextStyle(fontSize: 32, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 24),
          Row(
            children: [
              const SizedBox(width: 16),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () async {
                    final result = await Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => ChargeScreen(userId: userId),
                      ),
                    );
                    if (result == true) {
                      _fetchUserData(userId);
                      _fetchTransactions(userId);
                    }
                  },
                  icon: const Icon(Icons.add_circle_outline),
                  label: const Text('충전하기'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.blue[100],
                    foregroundColor: Colors.black,
                    elevation: 0,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () async {
                    final result = await Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => RefundScreen(userId: userId),
                      ),
                    );
                    if (result == true) {
                      _fetchUserData(userId);
                      _fetchTransactions(userId);
                    }
                  },
                  icon: const Icon(Icons.remove_circle_outline),
                  label: const Text('환불하기'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.grey[100],
                    foregroundColor: Colors.black,
                    elevation: 0,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 16),
            ],
          ),
          const SizedBox(height: 16),
          Container(
            color: const Color(0xFFF4F6F8),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 6),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    const Padding(
                      padding: EdgeInsets.only(right: 4),
                      child: Icon(
                        Icons.calendar_today,
                        size: 20,
                        color: Colors.black,
                      ),
                    ),
                    ElevatedButton(
                      onPressed: _showMonthFilterSheet,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFFF4F6F8),
                        foregroundColor: Colors.black,
                        elevation: 0,
                        shadowColor: Colors.transparent,
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 8,
                        ),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(6),
                        ),
                        splashFactory: NoSplash.splashFactory,
                      ).copyWith(
                        elevation: MaterialStateProperty.all(0),
                        shadowColor: MaterialStateProperty.all(
                          Colors.transparent,
                        ),
                      ),
                      child: Text(_selectedMonthFilter),
                    ),
                  ],
                ),

                Row(
                  children: [
                    const Padding(
                      padding: EdgeInsets.only(right: 0),
                      child: Icon(
                        Icons.attach_money,
                        size: 20,
                        color: Colors.black,
                      ),
                    ),
                    ElevatedButton(
                      onPressed: _showFilterSheet,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFFF4F6F8),
                        foregroundColor: Colors.black,
                        elevation: 0,
                        shadowColor: Colors.transparent,
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 8,
                        ),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(6),
                        ),
                        splashFactory: NoSplash.splashFactory,
                      ).copyWith(
                        elevation: MaterialStateProperty.all(0),
                        shadowColor: MaterialStateProperty.all(
                          Colors.transparent,
                        ),
                      ),
                      child: Text(_selectedFilter),
                    ),
                  ],
                ),
              ],
            ),
          ),

          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
              child:
                  filteredTransactions.isEmpty
                      ? const Center(child: Text('거래 내역이 없습니다.'))
                      : ListView.builder(
                        itemCount: sortedDates.length,
                        itemBuilder: (context, index) {
                          final date = sortedDates[index];
                          final transactionsOnDate = groupedTransactions[date]!;
                          return Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const SizedBox(height: 10),
                              Text(
                                DateFormat(
                                  'M월 d일',
                                  'ko_KR',
                                ).format(DateTime.parse(date)),
                                style: const TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.black87,
                                ),
                              ),
                              const SizedBox(height: 10),
                              ...transactionsOnDate.asMap().entries.map((
                                entry,
                              ) {
                                final tx = entry.value;
                                transactionsOnDate.length - 1;
                                return Column(
                                  children: [_buildTransactionItem(tx)],
                                );
                              }).toList(),
                            ],
                          );
                        },
                      ),
            ),
          ),
        ],
      ),
    );
  }
}
