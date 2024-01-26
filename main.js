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
            Sign(req, res, resJson, `google-${formattedInfo.id}`, formattedInfo.name);
        })
        .catch((error) => {
            let stamp = date.getTime();
            console.log('_SIGN_Error  /  ip: '+ip+'  /  '+stamp);
            console.log(error);
            
            resJson.msg = 'Google에 정보를 요청하던 중 오류가 발생하였습니다. _SIGN_Error: '+stamp.toString();
            
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
            Sign(req, res, resJson, `kakao-${formattedInfo.id}`, formattedInfo.kakao_account.profile.nickname);
        })
        .catch((error) => {
            let stamp = date.getTime();
            console.log('_SIGN_Error  /  ip: '+ip+'  /  '+stamp);
            console.log(error);
            
            resJson.msg = '카카오에 정보를 요청하던 중 오류가 발생하였습니다. _SIGN_Error: '+stamp.toString();
            
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
        codeRes = await codeRes.json();
    } 
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  code: '+code+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        
        res.send(resJson);
        
        return;
    }
    
    if(InjectionCheck(`${codeRes.access_token}`, regexAccessToken)){
        const info = await fetch(`https://openapi.naver.com/v1/nid/me`, {
            headers: {
                'Authorization': `Bearer ${codeRes.access_token}`,
            },
        });
        info.json().then((formattedInfo) => {
            if(formattedInfo.message == 'success'){
                Sign(req, res, resJson, `naver-${formattedInfo.response.id}`, formattedInfo.response.name);
            }
            else{
                let stamp = date.getTime();
                console.log(`_SIGN_Error  /  ip: ${ip}  /  ${formattedInfo}  /  `+stamp);
                
                resJson.msg = '네이버에 정보를 요청하던 중 오류가 발생하였습니다. _SIGN_Error: '+stamp.toString();
                
                res.send(resJson);
                
                return;
            }
        })
        .catch((error) => {
            let stamp = date.getTime();
            console.log('_SIGN_Error  /  ip: '+ip+'  /  '+stamp);
            console.log(error);
            
            resJson.msg = '네이버에 정보를 요청하던 중 오류가 발생하였습니다.';
            
            resJson.result = {error: error.message};
            
            res.send(resJson);
            
            return;
        });
    }
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  access_token: '+codeRes.access_token+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        
        res.send(resJson);
    }
});

const Sign = async(req, res, resJson, id, name) => {
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let conn = null;
    
    try{
        const query1 = 'SELECT * FROM users_table WHERE user_id=?';
        
        conn = await mysql.getConnection();
        
        const [result] = await conn.query(query1, id);
        
        if(result.length <= 0){
            const query2 = 'INSERT INTO users_table(user_id, user_nickname) VALUES(?, ?)';
            
            const [result2] = await conn.query(query2, [id, name]);
            
            const subQuery2 = 'INSERT INTO users_infos_table(user_id, user_position) VALUES(?, ?)';
            
            const [subResult2] = await conn.query(subQuery2, [id, '투자자']);
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
                const query4 = 'UPDATE users_table SET user_session=? WHERE user_id=?';
                
                const [result4] = await conn.query(query4, [session, id]);
                
                console.log('_SIGN_SUCCESS  /  ip: '+ip+'  /  id: '+id+'  /  '+date);
                
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
        console.log('_SIGN_Error  /  ip: '+ip+'  /  id: ' + id + '  /  ' + stamp);
        console.log(error);
        
        resJson.ok = false;
        resJson.msg =
            '데이터를 확인하던 중 오류가 발생하였습니다. _SIGN_Error: ' + `${stamp}`;
        resJson.result = {error: error.message};
        
        conn.release();
        
        res.send(resJson);
    }
};

app.post('/profil', async(req, res) => {
    const sessionID = req.body.datas.sessionID;
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    
    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;
    
    if(InjectionCheck(`${sessionID}`, regexAccessToken)){
        try{
            const query1 = 'SELECT user_id FROM users_table WHERE user_session=?';
            
            conn = await mysql.getConnection();
            
            const [result] = await conn.query(query1, sessionID);
            
            if(result.length <= 0){
                conn.release();
                resJson.ok = false;
                resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                resJson.result = null;
                res.send(resJson);
                return;
            }
            
            const query2 = 'SELECT * FROM users_infos_table WHERE user_id=?';
            
            const [result2] = await conn.query(query2, result[0].user_id);
            
            if(result2.length <= 0){
                let stamp = date.getTime();
                console.log('_PROFIL_Error_Null_infos  /  ip: '+ip+'  /  id: '+result[0].user_id+'  /  '+stamp);
                
                conn.release();
                resJson.ok = false;
                resJson.msg = '데이터상에 오류가 있습니다. 다음의 오류코드를 이용하여 관리자에게 문의해 주십시오. '+stamp.toString();
                resJson.result = null;
                res.send(resJson);
                return;
            }
            else{
                resJson.ok = true;
                resJson.msg = '프로필 로딩에 성공하였습니다.';
                resJson.result = {
                    id: result2[0].user_id.split('-')[0],
                    position: result2[0].user_position,
                    number: (result2[0].user_number == null ? '인증안함' : result2[0].user_number),
                    bank: (result2[0].user_bank == null ? '정보없음' : result2[0].user_bank),
                    bank_account: (result2[0].user_bank_account == null ? '정보없음' : result2[0].user_bank_account)
                };
                res.send(resJson);
                conn.release();
                return;
            }
        }
        catch(error){
            let stamp = date.getTime();
            console.log('_PROFIL_Error  /  ip: '+ip+'  /  ' + stamp);
            console.log(error);
        
            resJson.ok = false;
            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _PROFIL_Error: ' +stamp.toString();
            resJson.result = {error: error.message};
        
            res.send(resJson);
            
            conn.release();
        }
    }
    else{
        console.log('_INJECTION  /  ip: '+ip+'  /  sessionID: '+sessionID+'  /  '+date);
        
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        
        res.send(resJson);
    }
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