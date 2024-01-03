require('dotenv').config();
require('date');
const requestIp = require('request-ip');

const express = require('express');

const app = express();

const http = require('http');
const cors = require('cors');

const crypto = require('crypto');
const cookie =  require('cookie');
const cookieParser = require('cookie-parser');

const corsOptions = {
    origin: ['https://softhub-end.netlify.app', 'https://softhub-end.netlify.app/signIn', 'https://main--softhub-end.netlify.app', 'https://web.postman.co'],
    credentials: true,
};

app.use(express.urlencoded({ extended: true }));
app.use(cors(corsOptions));
app.use(cookieParser());

var MaxAge = 1000 * 60 * 60 * 1;

app.post('/signup', (req, res) => {
    console.log(req.headers.cookie);
    console.log(req.cookies);
    const salt = crypto.randomBytes(128).toString('base64');
    let email = req.body.signupEmail;
    let password = req.body.signupPassword;
    let nickname = req.body.signupNickname;
    let emailAuth = req.body.signupEmailAuth;
    if (epInjectionCheck(email, password) && nInjectionCheck(nickname)) {
        let isEmailExist;
        db.query(
            'SELECT user_address FROM users_table WHERE user_address = ?',
            [email],
            (error, mail) => {
                if (error) {
                    console.log('signup_SELECT_Error1: '+error);
                    res.json({ok: false, msg: '정보 확인중 오류가 발생하였습니다.'});
                }
                else if(mail.length <= 0){
                    isEmailExist = false;
                }
                else {
                    isEmailExist = true;
                }
                findNickname(isEmailExist, req, res, salt, email, password, nickname, emailAuth);
            }
        );
    } else {
        res.json({ ok: false, msg: '적절하지 않은 문자가 포함되어 있습니다.' });
    }
});

function findNickname(isEmailExist, req, res, salt, email, password, nickname, emailAuth) {
    let isNicknameExist;
    db.query('SELECT user_address FROM users_table WHERE user_id = ?', [nickname], (error, id) => {
        if (error) {
            console.log('signup_SELECT_Error2: '+error);
            res.json({ok: false, msg: '정보 확인중 오류가 발생하였습니다.'});
        } 
        else if(id.length<=0){
            isNicknameExist = false;
        }
        else {
            isNicknameExist = true;
        }
        checkInfo(isEmailExist, isNicknameExist, req, res, salt, email, password, nickname, emailAuth);
    });
}

function checkInfo(isEmailExist, isNicknameExist, req, res, salt, email, password, nickname, emailAuth) {
    if (isEmailExist) {
        res.json({ ok: false, msg: '이미 가입된 이메일입니다.' });
    } else if (isNicknameExist) {
        res.json({ ok: false, msg: '이미 존재하는 닉네임입니다.' });
    } else {
        if (emailAuth == 'null') {
            emailAuthorize(req, res);
        } else if (emailAuth == 'true') {
            var hashedPW = hashing(salt, password);
            db.query(
                'INSERT INTO users_table(user_id, user_position, user_pw, user_salt, user_address, created_at, updated_at) VALUES(?, ?, ?, ?, ?, now(), now())',
                [nickname, 'supporter', hashedPW, salt, email],
                (error, result) => {
                    if (error) {
                        console.log('signup_INSERT_query_Error: ' + error);
                        res.json({ ok: false, msg: '정보 저장 중 오류가 발생하였습니다.' });
                    } else {
                        let date = new Date();
                        let ip = requestIp.getClientIp(req);
                        console.log('SIGN_UP  /  email: '+email+"  /  ip: "+ip+"  /  "+date);
                        makeSession(email, res, '가입에 성공하였습니다.');
                    }
                }
            );
        } else {
            res.json({ ok: false, msg: '인증번호가 일치하지 않습니다.' });
        }
    }
}

app.post('/signin', (req, res) => {
    let email = req.body.signinEmail;
    let password = req.body.signinPassword;
    if (epInjectionCheck(email, password)) {
        db.query('SELECT * FROM users_table WHERE user_address=?', [email], (error, userInfo) => {
            if (error) {
                console.log('signin_SELECT_query_Error: ' + error);
                res.json({ ok: false, msg: '정보 확인중 오류가 발생하였습니다.' });
            } 
            else if(userInfo.length <= 0){
                res.json({ ok: false, msg: '해당 이메일로 가입된 계정이 없습니다.' });
            }
            else {
                if (hashing(userInfo[0].user_salt, password) == userInfo[0].user_pw) {
                    let date = new Date();
                    let ip = requestIp.getClientIp(req);
                    console.log('SIGN_IN  /  primary: '+userInfo[0].seq+"  /  id: "+userInfo[0].user_id+"  /  ip: "+ip+"  /  "+date);
                    makeSession(userInfo[0].user_address, res, '로그인 성공');
                } else {
                    res.json({ ok: false, msg: '비밀번호가 일치하지 않습니다.' });
                }
            }
        });
    } else {
        res.json({ ok: false, msg: '적절하지 않은 문자가 포함되어 있습니다.' });
    }
});

app.listen(process.env.PORT, '0.0.0.0' ,() => {
    console.log(`${process.env.PORT}번 포트에서 대기중`);
});

function hashing(salt, pw) {
    const hashedPassword = crypto
        .createHash('sha512')
        .update(pw + salt)
        .digest('hex');
    return hashedPassword;
}

const mysql = require('mysql');

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PW,
    database: process.env.DB_NAME,
});

const regexE = /[^a-zA-Z0-9!\?@\.]/;
const regexP = /[^a-zA-Z0-9!\?@]/;
const regexN = /[^a-zA-Z0-9가-힣]/;

function epInjectionCheck(e, p) {
    if (e.match(regexE) || p.match(regexP)) {
        return false;
    } else {
        return true;
    }
}

function nInjectionCheck(n) {
    if (n.match(regexN)) {
        return false;
    } else {
        return true;
    }
}

const nodeMailer = require('nodemailer');

const smtpTransport = nodeMailer.createTransport({
    pool: true,
    maxConnections: 1,
    service: 'naver',
    host: 'smtp.naver.com',
    port: 587,
    secure: false,
    requireTLS: true,
    auth: {
        user: process.env.AUTH_EMAIL_ADDRESS,
        pass: process.env.AUTH_EMAIL_PW,
    },
    tls: {
        rejectUnauthorized: false,
    },
});

var generateRandomNumber = (min, max) => {
    let randNum = Math.floor(Math.random() * (max - min + 1)) + min;

    return randNum;
};

var emailAuthorize = (req, res) => {
    const number = generateRandomNumber(111111, 999999);

    const mail = req.body.signupEmail;

    const mailOptions = {
        from: process.env.AUTH_EMAIL_ADDRESS,
        to: mail,
        subject: 'Softhub 인증메일',
        html: '<h1>인증번호를 입력해주세요<h1><br>' + number,
    };

    smtpTransport.sendMail(mailOptions, (error, response) => {
        console.log('response: ' + response);
        if (error) {
            console.log('sendMail_Error: ' + error);
            res.json({ ok: false, msg: '메일 전송에 실패하였습니다.' });
            smtpTransport.close();
        } else {
            let date = new Date();
            let ip = requestIp.getClientIp(req);
            console.log('AUTH_EMAIL  /  email: '+mail+"  /  ip: "+ip+"  /  "+date);
            res.json({ ok: true, msg: '메일 전송에 성공하였습니다.', authNum: number });
            smtpTransport.close();
        }
    });
};

function makeSession(address, res, msg){
    db.query('select seq from sessions_table where date_format(DATE_SUB(session_created_at, INTERVAL ? hour), "%Y%m%d%H") <= date_format(now(), "%Y%m%d%H")',
            [1],
            (error, result) => {
                if(error){
                    console.log('makeSession_SELECT_expired_query_Error: '+error);
                    res.json({ok: false, msg:'정보 저장중 오류가 발생하였습니다.'});
                }
                else if(result.length >= 1){
                    let target = '';
                    for (var i = 0; i < result.length; i++) {
                        target += `${result[i].seq}`;
                        if(!(i >= result.length-1)){
                            target += ',';
                        }
                    }
                    db.query('delete from sessions_table where seq in(?)',
                            [target],
                            (error2, result2) => {
                        if(error2){
                            console.log('makeSession_SELECT_expired_query2_Error: '+error2)
                            res.json({ok: false, msg:'정보 저장중 오류가 발생하였습니다.'});
                        }
                        else{
                            
                        }
                    });
                }
                else{
                    
                }
            });
    const salt2 = crypto.randomBytes(128).toString('base64');
    const param = Math.floor(Math.random() * (999999 - 111111 + 1)) + 111111;
    const session = hashing(salt2, param);
    db.query('SELECT * FROM sessions_table WHERE user_session=?',
            [session],
            (error, result) =>{
        if(error){
            console.log('makeSession_SELECT_query_Error: '+error);
            res.json({ok: false, msg:'정보 저장중 오류가 발생하였습니다.'});
        }
        else if(result.length>=1){
            makeSession(address, res, msg);
        }
        else{
            db.query('SELECT * FROM sessions_table WHERE user_session_address=?',
                    [address],
                    (error2, result2) => {
                if(error2){
                    console.log('makeSession_SELECT_query2_Error: '+error2);
                    res.json({ok: false, msg:'정보 저장중 오류가 발생하였습니다.'});
                }
                else if(result2.length >= 1){
                    db.query('UPDATE sessions_table SET user_session=?, session_created_at=now() WHERE user_session_address=?',
                            [session, address],
                            (error3, result3) => {
                        if(error3){
                            console.log('makeSession_SELECT_query3_Error: '+error3);
                            res.json({ok: false, msg:'정보 저장중 오류가 발생하였습니다.'});
                        }
                        else{
                            res.json({ok: true, msg: msg, cookie: [session, MaxAge]});
                        }
                    })
                }
                else{
                    db.query('INSERT INTO sessions_table(user_session, user_session_address, session_created_at) VALUES(?, ?, now())',
                            [session, address],
                            (error4, result4) => {
                        if(error4){
                            console.log('makeSession_SELECT_query4_Error: '+error4);
                            res.json({ok: false, msg:'정보 저장중 오류가 발생하였습니다.'});
                        }
                        else{
                            res.json({ok: true, msg: msg, cookie: [session, MaxAge]});
                        }
                    })
                }
            })
        }
    })
}