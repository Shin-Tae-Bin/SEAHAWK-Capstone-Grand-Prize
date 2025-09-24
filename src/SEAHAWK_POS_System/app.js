require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// 요청 로깅
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.url}`);
  console.log('Body:', req.body);
  next();
});

// DB 연결 (기존과 동일)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

});

function getRestaurant(menuName, amount) {
  const match = menuName.match(/식권\s*(\d+)\s*개/);
  const ticketCount = match ? parseInt(match[1], 10) : 1;
  const perTicket = amount / ticketCount;
  if (perTicket === 4800) return '아질리아';
  if (perTicket === 5000) return '피오니';
  return '기타';
}

const POS_LOGIN_SECRET = 'pos_login_secret';

// 1. POS 운영자 로그인
app.post('/login', async (req, res) => {
  try {
    const password = (req.body.password || '').trim();
    const username = (req.body.username || '').trim();
    const [rows] = await pool.query('SELECT * FROM pos_accounts WHERE username = ? LIMIT 1', [username]);
    if (!rows.length) {
      return res.status(401).json({ success: false, message: '인증 실패: 계정 없음' });
    }
    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) {
      return res.status(401).json({ success: false, message: '인증 실패: 비밀번호 불일치' });
    }
    // username이 pos_admin이면 아질리아, pos_admin2면 피오니로 매핑
    let restaurant = '';
    if (username === 'pos_admin') restaurant = '아질리아';
    else if (username === 'pos_admin2') restaurant = '피오니';
    else restaurant = '기타';

    const token = jwt.sign({ posId: rows[0].id, username: rows[0].username, restaurant }, POS_LOGIN_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token, restaurant });
  } catch (error) {
    console.error('로그인 에러:', error);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// 2. QR 결제
app.post('/pay', async (req, res) => {
  const posToken = req.headers.authorization?.split(' ')[1];
  if (!posToken) {
    return res.status(401).json({ success: false, message: 'POS 로그인 필요' });
  }
  try {
    jwt.verify(posToken, POS_LOGIN_SECRET);

    const { qrToken, ticketCount } = req.body;
    if (!qrToken || !ticketCount) {
      return res.status(400).json({ success: false, message: 'qrToken 또는 ticketCount가 누락되었습니다.' });
    }
    
    // JWT 토큰에서 식당 정보 추출
    const decoded = jwt.decode(posToken);
    console.log('🔍 JWT 토큰 전체 내용:', decoded);
    const restaurant = decoded.restaurant;
    console.log('🔍 JWT 토큰에서 추출한 식당:', restaurant);
    console.log('🔍 식당 타입:', typeof restaurant);
    
    let ticketPoint;
    if (restaurant === '피오니') {
      ticketPoint = 5000;
      console.log('✅ 피오니로 설정됨 - 5000원');
    } else {
      ticketPoint = 4800; // 아질리아 기본값
      console.log('✅ 아질리아로 설정됨 - 4800원');
    }
    
    console.log('🔍 최종 설정된 가격:', ticketPoint);

    const cleanToken = qrToken.split('#')[0];
    const parts = cleanToken.split('|');
    if (parts.length !== 3) {
      return res.status(400).json({ success: false, message: '잘못된 QR 형식' });
    }
    const [userId, hash, dateString] = parts;
    
    // # 뒤의 실제 타임스탬프 추출
    const actualTimestamp = qrToken.split('#')[1];
    
    console.log('🔍 QR 토큰 파싱:');
    console.log('  - 원본 토큰:', qrToken);
    console.log('  - 정리된 토큰:', cleanToken);
    console.log('  - 파싱된 부분:', parts);
    console.log('  - userId:', userId);
    console.log('  - hash:', hash);
    console.log('  - dateString:', dateString);
    console.log('  - actualTimestamp:', actualTimestamp);

    // QR 토큰 타임스탬프 검증 (1분 만료)
    const currentTime = Date.now();
    const tokenTime = parseInt(actualTimestamp, 10);
    
    // 타임스탬프가 유효한 숫자인지 확인
    if (isNaN(tokenTime)) {
      console.log('❌ 타임스탬프가 유효한 숫자가 아님:', actualTimestamp);
      return res.status(400).json({ 
        success: false, 
        message: '잘못된 QR 토큰 형식입니다.' 
      });
    }
    
    // 타임스탬프가 미래 시간인지 확인
    if (tokenTime > currentTime) {
      console.log('❌ 타임스탬프가 미래 시간임:', tokenTime, '>', currentTime);
      return res.status(400).json({ 
        success: false, 
        message: '잘못된 QR 토큰입니다.' 
      });
    }
     
    const timeDiff = currentTime - tokenTime;
    const expirationTime = 60000; // 1분 (60000ms)
    
    console.log('🔍 QR 토큰 타임스탬프 검증:');
    console.log('  - 현재 시간:', currentTime);
    console.log('  - 토큰 시간:', tokenTime);
    console.log('  - 시간 차이:', timeDiff, 'ms');
    console.log('  - 만료 시간:', expirationTime, 'ms');
    console.log('  - 만료 여부:', timeDiff > expirationTime ? '만료됨' : '유효함');
    
    if (timeDiff > expirationTime) {
      console.log('❌ QR 토큰 만료됨 - 결제 거부');
      return res.status(400).json({ 
        success: false, 
        message: 'QR 토큰이 만료되었습니다. (1분 초과)' 
      });
    }
    
    console.log('✅ QR 토큰 유효함 - 결제 진행');

    // QR 토큰 유효성 검증 (생략)
    const [qrRow] = await pool.query(`
      SELECT * FROM qr_issued_tokens 
      WHERE user_id = ? 
        AND hash = ? 
        AND is_used = 0 
      LIMIT 1
    `, [userId, hash]);

    if (!qrRow.length) {
      return res.status(400).json({ 
        success: false, 
        message: '유효하지 않거나 이미 사용된 QR입니다.' 
      });
    }

    // QR 토큰 사용 처리 (1분이 지난 토큰만 is_used = 1로 변경)
    if (timeDiff > expirationTime) {
      // 1분이 지난 토큰은 사용 처리
      await pool.query(
        'UPDATE qr_issued_tokens SET is_used = 1 WHERE id = ?',
        [qrRow[0].id]
      );
    }
    // 1분이 지나지 않은 토큰은 그대로 두어 재사용 가능하게 함

    // 식당별 가격 동적 계산
    const menuName = `식권 ${ticketCount}개`;

    const conn = await pool.getConnection();
    await conn.beginTransaction();
    try {
      const [user] = await pool.query(
        'SELECT virtual_points FROM users WHERE id = ? FOR UPDATE',
        [userId]
      );  
      if (!user.length || user[0].virtual_points < ticketPoint * Number(ticketCount)) {
        await conn.rollback();
        conn.release();
        return res.status(400).json({ success: false, message: '포인트 부족' });
      }
      await conn.query(
        'UPDATE users SET virtual_points = virtual_points - ? WHERE id = ?',
        [ticketPoint * Number(ticketCount), userId]
      );
      // restaurant 컬럼 저장
      await conn.query(
        'INSERT INTO pos_payments (user_id, menu_name, amount, payment_time, status, restaurant) VALUES (?, ?, ?, NOW(), ?, ?)',
        [userId, menuName, ticketPoint * Number(ticketCount), 'success', restaurant]
      );
      await conn.commit();
      conn.release();
      res.json({ success: true, message: '결제 성공', deducted: ticketPoint * Number(ticketCount), restaurant });
    } catch (dbError) {
      await conn.rollback();
      conn.release();
      throw dbError;
    }
  } catch (err) {
    res.status(500).json({ success: false, message: '결제 처리 중 오류: ' + err.message });
  }
});

// 3. 카드/현금 결제
app.post('/manual_pay', async (req, res) => {
  let { menuName, amount, method, cardNumber } = req.body;

  // menuName을 프론트에서 온 그대로 사용!
  // const match = menuName.match(/\d+/);
  // const ticketCount = match ? parseInt(match[0], 10) : 1;
  // menuName = `식권 ${ticketCount}개`;

  // 식당명 구하기
  const restaurant = getRestaurant(menuName, amount);

  if (!menuName || !method) {
    return res.status(400).json({ success: false, message: '메뉴명과 결제방식은 필수입니다.' });
  }
  amount = Number(amount);
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ success: false, message: '올바른 금액을 입력해주세요.' });
  }
  method = method.toLowerCase();
  if (!['card', 'cash'].includes(method)) {
    return res.status(400).json({ success: false, message: '결제방식은 card 또는 cash만 가능합니다.' });ㅁ
  }
  if (method === 'card' && (!cardNumber || !/^\d{16}$/.test(cardNumber))) {
    return res.status(400).json({ success: false, message: '카드번호는 16자리 숫자여야 합니다.' });
  }

  try {
    await pool.query(
      'INSERT INTO manual_payments (menu_name, amount, payment_time, payment_method, card_number, restaurant) VALUES (?, ?, NOW(), ?, ?, ?)',
      [menuName.substring(0, 255), amount, method, method === 'card' ? cardNumber : null, restaurant]
    );
    res.json({ success: true, message: `${method.toUpperCase()} 결제 완료`, restaurant });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류: ' + err.message });
  }
});
 
const port = process.env.PORT || 3636;
app.listen(port, () => console.log(`POS 결제 서버 실행 중 (포트:${port})`));

// 만료된 QR 토큰을 주기적으로 삭제하는 스케줄러 (5분마다 실행)
setInterval(async () => {
  try {
    const sixMinutesAgo = Date.now() - 360000; // 6분 전 (1분 만료 + 5분 대기)
    const [result] = await pool.query(
      'DELETE FROM qr_issued_tokens WHERE timestamp < ?',
      [sixMinutesAgo]
    );
    if (result.affectedRows > 0) {
      console.log(`🗑️ 만료된 QR 토큰 ${result.affectedRows}개 삭제됨 (만료 후 5분 경과)`);
    }
  } catch (error) {
    console.error('QR 토큰 삭제 중 오류:', error);
  }
}, 300000); // 5분마다 실행 (300000ms)

bcrypt.hash('pos21234', 10, (err, hash) => {
  if (err) throw err;
  console.log(hash);
});

