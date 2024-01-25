require('dotenv').config();

require('date');
const requestIp = require('request-ip');

const express = require('express');

const app = express();

const http = require('http');
const cors = require('cors');

const crypto = require('crypto');

const cookie = require('cookie');
const cookieParser = require('cookie-parser');

const nodeMailer = require('nodemailer');

const mysql = require('./mysql');

const fs = require('fs');

const {Storage} = require('@google-cloud/storage');

import fetch from 'node-fetch';

const corsOptions = {
    origin: [
        'https://fundhub.netlify.app',
        'https://main--fundhub.netlify.app',
        'https://web.postman.co',
    ],
    credentials: true,
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors(corsOptions));
app.use(cookieParser());

app.post('/oAuthGoogle', async (req, res) =>{
    console.log(req.body.datas);
    const access_token = req.body.datas.access_token;
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    
    let conn = null;
    
    if(InjectionCheck(access_token, regexAccessToken)){
        const info = await fetch(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${access_token}`);
        console.log(info);
    }
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  access_token: '+access_token+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
    }
    res.send(resJson);
})

app.post('/signUp', async (req, res) => {
    const salt = crypto.randomBytes(128).toString('base64');
    const access_token = req.body.datas.access_token;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (
        epInjectionCheck(email, password) &&
        nInjectionCheck(nickname) &&
        nInjectionCheck(emailAuth)
    ) {
        try {
            //check is there same email
            const query1 = 'SELECT user_address FROM users_table WHERE user_address = ?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, email);

            if (result.length >= 1) {
                conn.release();
                resJson.msg = '이미 존재하는 이메일 계정 입니다.';
                res.send(resJson);
                return;
            }

            //check is there same nickname
            const query2 = 'SELECT user_id FROM users_table WHERE user_id = ?';

            const [result2] = await conn.query(query2, nickname);

            if (result2.length >= 1) {
                conn.release();
                resJson.msg = '이미 존재하는 닉네임 입니다.';
                res.send(resJson);
                return;
            }

            //authorize email
            if (emailAuth == 'null') {
                emailAuthorize(req, res, resJson);
                conn.release();
                return;
            } else if (emailAuth == 'true') {
                const query3 =
                    'INSERT INTO users_table(user_id, user_position, user_pw, user_salt, user_address, created_at, updated_at) VALUES(?, ?, ?, ?, ?, now(), now())';

                const [result3] = await conn.query(query3, [
                    nickname,
                    'supporter',
                    hashing(salt, password),
                    salt,
                    email,
                ]);

                resJson.ok = true;
                resJson.msg = '회원가입에 성공하셨습니다.';

                console.log(
                    '_SIGN_UP_Success  /  ip: ' + ip + '  /  email: ' + email + '  /  ' + date
                );

                makeSession(conn, req, res, resJson);
                conn.release();
                return;
            } else {
                resJson.msg = '인증번호가 일치하지 않습니다.';
            }
            conn.release();
        } catch (error) {
            let stamp = date.getTime();
            console.log('_SIGN_UP_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SIGN_UP_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        resJson.msg =
            '요청에 적절하지 않은 문자 (한글, 영어, 숫자, !, ?, @, . 외의 문자) 가 포함되어 있습니다.';
    }
    res.send(resJson);
});

app.listen(process.env.PORT, '0.0.0.0', () => {
    console.log(`${process.env.PORT}번 포트에서 대기중`);
});

function hashing(salt, pw) {
    const hashedPassword = crypto
        .createHash('sha512')
        .update(pw + salt)
        .digest('hex');
    return hashedPassword;
}

const regexAccessToken = /[^a-zA-Z0-9\.\-_]/;
const regexEmail = /[^a-zA-Z0-9!\?@\.]/;
const regexPw = /[^a-zA-Z0-9!\?@]/;
const regexNick = /[^a-zA-Z0-9가-힣]/;
const regexText = /[^a-zA-Z0-9ㄱ-ㅎㅏ-ㅣ가-힣!\?@\.,\s]/;

function InjectionCheck(target, regex){
    if(!target.match(regex)){
        return true;
    }
    else{
        return false;
    }
}