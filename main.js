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

const corsOptions = {
    origin: [
        'https://fundhub.netlify.app',
        'https://main--fundhub.netlify.app',
        'https://web.postman.co',
    ],
    credentials: true,
};

const fetch = (link, message) => import('node-fetch').then(({default: fetch}) => fetch(link, message));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors(corsOptions));
app.use(cookieParser());

app.post('/oAuthGoogle', async (req, res) =>{
    const access_token = req.body.datas.access_token;
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    
    if(InjectionCheck(`${access_token}`, regexAccessToken)){
        const info = await fetch(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${access_token}`, {});
        info.json().then((formattedInfo) => {
            console.log(formattedInfo);
            Sign(req, res, resJson, formattedInfo.email, formattedInfo.name);
        })
        .catch((error) => {
            resJson.msg = 'Google에 정보를 요청하던 중 오류가 발생하였습니다.';
            
            resJson.result = {error: error.message};
            
            res.send(resJson);
            
            return;
        });
    }
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  access_token: '+access_token+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        
        res.send(resJson);
    }
});

app.post('/oAuthKakao', async(req, res) => {
    const access_token = req.body.datas.access_token;
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    
    if(InjectionCheck(`${access_token}`, regexAccessToken)){
        const info = await fetch(`https://kapi.kakao.com/v2/user/me`, {
            headers: {
                'Authorization': `Bearer ${access_token}`,
                'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
            },
        });
        info.json().then((formattedInfo) => {
            if(formattedInfo.kakao_account.is_email_valid && formattedInfo.kakao_account.is_email_verified){
                console.log(formattedInfo);
                Sign(req, res, resJson, formattedInfo.kakao_account.email, formattedInfo.kakao_account.profile.nickname);
            }
            else{
                resJson.msg = '카카오계정에 등록된 이메일이 인증된 이메일이 아닙니다. 카카오계정에서 이메일을 인증하여주세요.'
                
                res.send(resJson);
                
                return;
            }
        })
        .catch((error) => {
            resJson.msg = '카카오에 정보를 요청하던 중 오류가 발생하였습니다.';
            
            resJson.result = {error: error.message};
            
            res.send(resJson);
            
            return;
        });
    }
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  access_token: '+access_token+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        
        res.send(resJson);
    }
});

app.post('/oAuthNaver', async(req, res) => {
    const code = req.body.datas.code;
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let codeRes;
    
    if(InjectionCheck(`${code}`, regexAccessToken)){
        const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
        const NAVER_SECRET_KEY = process.env.NAVER_SECRET_KEY;
        
        const rand = 'naver-'+Math.floor(Math.random() * 1000000000).toString();
        
        codeRes = await fetch(`https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&client_id=${NAVER_CLIENT_ID}&client_secret=${NAVER_SECRET_KEY}&code=${code}&state=${rand}`, {});
        codeRes = codeRes.json();
    } 
    console.log(codeRes);
    if(InjectionCheck(`${codeRes.access_token}`, regexAccessToken)){
        const info = await fetch(`https://openapi.naver.com/v1/nid/me`, {
            headers: {
                'Authorization': `Bearer ${codeRes.access_token}`,
            },
        });
        info.json().then((formattedInfo) => {
            console.log(formattedInfo);
        })
        .catch((error) => {
            resJson.msg = '네이버에 정보를 요청하던 중 오류가 발생하였습니다.';
            
            resJson.result = {error: error.message};
            
            res.send(resJson);
            
            return;
        });
    }
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  access_token: '+access_token+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        
        res.send(resJson);
    }
});

const Sign = async(req, res, resJson, email, name) => {
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let conn = null;
    
    try{
        const query1 = 'SELECT * FROM users_table WHERE user_email=?';
        
        conn = await mysql.getConnection();
        
        const [result] = await conn.query(query1, email);
        
        if(result.length <= 0){
            const query2 = 'INSERT INTO users_table(user_email, user_nickname) VALUES(?, ?)';
            
            const [result2] = await conn.query(query2, [email, name]);
            
            const subQuery2 = 'INSERT INTO users_infos_table(user_email, user_position) VALUES(?, ?)';
            
            const [subResult2] = await conn.query(subQuery2, [email, '투자자']);
        }
        
        const salt = crypto.randomBytes(128).toString('base64');
        
        const hashLoop = async () => {
            const rand = Math.floor(Math.random() * 1000000);
            const session = hashing(salt, rand);
            
            const query3 = 'SELECT * FROM users_table WHERE user_session=?';
            
            const [result3] = await conn.query(query3, session);
            
            if(result3.length > 0){
                hashLoop();
            }
            else{
                const query4 = 'UPDATE users_table SET user_session=? WHERE user_email=?';
                
                const [result4] = await conn.query(query4, [session, email]);
                
                console.log('_SIGN_SUCCESS  /  ip: '+ip+'  /  email: '+email+'  /  '+date);
                
                resJson.ok = true;
                
                resJson.msg = `환영합니다 ${result.length <= 0 ? name : result[0].user_nickname}님`;
                
                resJson.result = {sessionID: session, nickname: (result.length <= 0 ? name : result[0].user_nickname)};
                
                res.send(resJson);
            }
        };
        
        hashLoop();
    }
    catch(error){
        let stamp = date.getTime();
        console.log('_SIGN_Error  /  ip: '+ip+'  /  email: ' + email + '  /  ' + stamp);
        console.log(error);
        
        resJson.ok = false;
        resJson.msg =
            '데이터를 확인하던 중 오류가 발생하였습니다. _SIGN_UP_Error: ' + `${stamp}`;
        resJson.result = {error: error.message};
        
        conn.release();
        
        res.send(resJson);
    }
};

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
            resJson.result = {error: error.message};

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

function hashing(salt, rand) {
    const hashed = crypto
        .createHash('sha512')
        .update(rand + salt)
        .digest('hex');
    return hashed;
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