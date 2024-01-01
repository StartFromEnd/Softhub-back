require('dotenv').config();

const express = require('express');
const app = express();

const http = require('http');
const cors = require('cors');

const crypto = require('crypto');

const corsOptions = {
    origin: ['https://softhub-end.netlify.app', 'https://main--softhub-end.netlify.app', 'https://web.postman.co'],
    credentials: true,
};

app.use(express.urlencoded({ extended: true }));
app.use(cors(corsOptions));

app.post('/signup', (req, res) => {
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
                    return;
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
            return;
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
        return;
    } else if (isNicknameExist) {
        res.json({ ok: false, msg: '이미 존재하는 닉네임입니다.' });
        return;
    } else {
        if (emailAuth == 'null') {
            emailAuthorize(req, res);
        } else if (emailAuth == 'true') {
            var hashedPW = hashing(salt, password);
            console.log(hashedPW);
            db.query(
                'INSERT INTO users_table(user_id, user_position, user_pw, user_salt, user_address, created_at, updated_at) VALUES(?, ?, ?, ?, ?, now(), now())',
                [nickname, 'supporter', hashedPW, salt, email],
                (error, result) => {
                    if (error) {
                        console.log('signup_INSERT_query_Error: ' + error);
                        res.json({ ok: false, msg: '정보 저장 중 오류가 발생하였습니다.' });
                        return;
                    } else {
                        res.json({ ok: true, msg: '가입에 성공하였습니다.' });
                        return;
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
            if (userInfo == undefined) {
                console.log('signin_SELECT_query_Error: ' + error);
                res.json({ ok: false, msg: '해당 이메일로 가입된 계정이 없습니다.' });
                return;
            } else {
                if (hashing(userInfo[0].user_salt, password) == userInfo[0].user_pw) {
                    res.json({
                        ok: true,
                        msg: '로그인 성공',
                        nickname: userInfo[0].user_id,
                        position: userInfo[0].user_position,
                        email: userInfo[0].user_address,
                    });
                    return;
                } else {
                    res.json({ ok: false, msg: '비밀번호가 일치하지 않습니다.' });
                    return;
                }
            }
        });
    } else {
        res.json({ ok: false, msg: '적절하지 않은 문자가 포함되어 있습니다.' });
    }
});

app.listen(process.env.PORT, () => {
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
            return;
        } else {
            res.json({ ok: true, msg: '메일 전송에 성공하였습니다.', authNum: number });
            smtpTransport.close();
            return;
        }
    });
};