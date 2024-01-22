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
        'https://softhub-picwm.run.goorm.site/',
        'https://softhub-end.netlify.app',
        'https://softhub-end.netlify.app/signIn',
        'https://main--softhub-end.netlify.app',
        'https://web.postman.co',
    ],
    credentials: true,
};

app.use(express.urlencoded({ extended: true }));
app.use(cors(corsOptions));
app.use(cookieParser());

var MaxAge = 400; //days

app.post('/signUp', async (req, res) => {
    const salt = crypto.randomBytes(128).toString('base64');
    let email = req.body.email;
    let password = req.body.password;
    let nickname = req.body.nickname;
    let emailAuth = req.body.variable1;

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

app.post('/signIn', async (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (epInjectionCheck(email, password)) {
        try {
            const query1 = 'SELECT * FROM users_table WHERE user_address=?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, email);

            if (result.length <= 0) {
                conn.release();
                resJson.msg = '해당 이메일로 가입된 계정이 없습니다.';
                res.send(resJson);
                return;
            }

            if (hashing(result[0].user_salt, password) == result[0].user_pw) {
                resJson.ok = true;
                resJson.msg = '로그인에 성공하셨습니다.';

                console.log(
                    '_SIGN_IN_Success  /  ip: ' + ip + '  /  email: ' + email + '  /  ' + date
                );

                makeSession(conn, req, res, resJson);

                conn.release();
                return;
            } else {
                resJson.msg = '비밀번호가 일치하지 않습니다.';
            }
            conn.release();
        } catch (error) {
            let stamp = date.getTime();

            console.log('_SIGN_IN_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SIGN_IN_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        resJson.msg =
            '적절하지 않은 문자 (한글, 영어, 숫자, !, ?, @, . 외의 문자) 가 포함되어 있습니다.';
    }
    res.send(resJson);
});

app.post('/sessionCheck', async (req, res) => {
    let sessionID = req.body.sessionID;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (nInjectionCheck(sessionID)) {
        try {
            const query1 = 'SELECT * FROM sessions_table WHERE user_session=?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, sessionID);

            if (result.length <= 0) {
                conn.release();
                resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                res.send(resJson);
                return;
            }

            const query2 = 'SELECT * FROM users_table WHERE user_address=?';

            const [result2] = await conn.query(query2, result[0].user_session_address);

            if (result2.length <= 0) {
                conn.release();
                resJson.msg = '존재하지 않는 계정에 대한 세션입니다. 다시 로그인 해 주십시오.';
                res.send(resJson);
                return;
            } else {
                resJson.ok = true;
                resJson.msg = '세션인증에 성공하셨습니다.';
                resJson.result = [
                    result2[0].user_id,
                    result2[0].user_position,
                    result2[0].user_address,
                ];
                res.send(resJson);

                const query3 =
                    'UPDATE sessions_table SET session_created_at=DATE_ADD(now(), INTERVAL ? day) WHERE user_session=?';

                const [result3] = await conn.query(query3, [MaxAge, sessionID]);

                conn.release();
                return;
            }
        } catch (error) {
            let stamp = date.getTime();

            console.log('_SESSION_CHECK_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SESSION_CHECK_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        console.log(
            '_SESSION_INJECTION  /  ip: ' + ip + '  /  session: ' + `${sessionID}` + '  /  ' + date
        );
        resJson.msg = '세션에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
    }
    res.send(resJson);
});

app.post('/signOut', async (req, res) => {
    let sessionID = req.body.sessionID;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (nInjectionCheck(sessionID)) {
        try {
            const query1 = 'DELETE FROM sessions_table WHERE user_session=?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, sessionID);

            resJson.ok = true;
            resJson.msg = '로그아웃에 성공하셨습니다.';

            console.log('_SIGN_OUT_Success  /  ip: ' + ip + '  /  ' + date);

            conn.release();
        } catch (error) {
            let stamp = date.getTime();

            console.log('_SIGN_OUT_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SIGN_OUT_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        console.log(
            '_SESSION_INJECTION  /  ip: ' + ip + '  /  session: ' + `${sessionID}` + '  /  ' + date
        );
        resJson.msg = '세션에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
    }
    res.send(resJson);
});

app.post('/profil', async (req, res) => {
    let sessionID = req.body.sessionID;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (nInjectionCheck(sessionID)) {
        try {
            const query1 = 'SELECT * FROM sessions_table WHERE user_session = ?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, sessionID);

            if (result.length <= 0) {
                conn.release();
                resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                res.send(resJson);
                return;
            }

            const query2 = 'SELECT * FROM users_table WHERE user_address = ?';

            const [result2] = await conn.query(query2, result[0].user_session_address);

            if (result2.length <= 0) {
                conn.release();
                resJson.msg = '존재하지 않는 계정에 대한 세션입니다. 다시 로그인 해 주십시오.';
                res.send(resJson);
                return;
            } else {
                resJson.ok = true;
                resJson.msg = '프로필 로딩에 성공하셨습니다.';
                resJson.result = [
                    result2[0].user_id,
                    result2[0].user_position,
                    result2[0].user_address,
                    result2[0].user_bank_account,
                ];
            }
            conn.release();
        } catch (error) {
            let stamp = date.getTime();

            console.log('_Profil_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _Profil_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        console.log(
            '_SESSION_INJECTION  /  ip: ' + ip + '  /  session: ' + `${sessionID}` + '  /  ' + date
        );
        resJson.msg = '세션에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
    }
    res.send(resJson);
});

app.post('/faqList', async (req, res) => {
    let sessionID = req.body.sessionID;
    let option = req.body.variable1;
    let nowPage = req.body.variable2;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (option == 'private') {
        if (nInjectionCheck(sessionID) && nInjectionCheck(option) && nInjectionCheck(nowPage)) {
            try {
                const query1 = 'SELECT * FROM sessions_table WHERE user_session = ?';

                conn = await mysql.getConnection();

                const [result] = await conn.query(query1, sessionID);

                if (result.length <= 0) {
                    conn.release();
                    resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                    res.send(resJson);
                    return;
                }

                const query2 =
                    'SELECT COUNT(*) as cnt FROM faqs_table WHERE faq_from_whom=? AND faq_option=?';

                const [result2] = await conn.query(query2, [
                    result[0].user_session_address,
                    option,
                ]);

                let faqNum = result2[0].cnt;
                let startFaqNum = 10 * (nowPage - 1);
                let limitFaqNum = faqNum >= startFaqNum + 10 ? 10 : faqNum - startFaqNum;

                const query3 =
                    'SELECT * FROM faqs_table WHERE faq_from_whom=? AND faq_option=? ORDER BY seq DESC Limit ?, ?';

                const [result3] = await conn.query(query3, [
                    result[0].user_session_address,
                    option,
                    startFaqNum,
                    limitFaqNum,
                ]);

                resJson.ok = true;
                resJson.msg = '문의사항 로딩에 성공하셨습니다.';
                resJson.result = [faqNum, result3];

                conn.release();
            } catch (error) {
                let stamp = date.getTime();

                console.log('_FAQ_LIST_Error  /  ip: ' + ip + '  /  ' + stamp);
                console.log(error);

                resJson.msg =
                    '데이터를 확인하던 중 오류가 발생하였습니다. _FAQ_LIST_Error: ' + `${stamp}`;
                resJson.result = [error.message];

                conn.release();
            }
        } else {
            console.log(
                '_INJECTION  /  ip: ' +
                    ip +
                    '  /  session: ' +
                    `${sessionID}` +
                    '  /  option: ' +
                    option +
                    '  /  nowPage: ' +
                    nowPage +
                    '  /  ' +
                    date
            );
            resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        }
        res.send(resJson);
    } else {
        if (nInjectionCheck(option) && nInjectionCheck(nowPage)) {
            try {
                conn = await mysql.getConnection();

                const query1 = 'SELECT COUNT(*) as cnt FROM faqs_table WHERE faq_option=?';

                const [result] = await conn.query(query1, [option]);

                let faqNum = result[0].cnt;
                let startFaqNum = 10 * (nowPage - 1);
                let limitFaqNum = faqNum >= startFaqNum + 10 ? 10 : faqNum - startFaqNum;

                const query2 = 'SELECT * FROM faqs_table WHERE faq_option=? ORDER BY seq DESC';

                const [result2] = await conn.query(query2, [option]);

                resJson.ok = true;
                resJson.msg = '문의사항 로딩에 성공하셨습니다.';
                resJson.result = [faqNum, result2];

                conn.release();
            } catch (error) {
                let stamp = date.getTime();

                console.log('_FAQ_LIST_Error  /  ip: ' + ip + '  /  ' + stamp);
                console.log(error);

                resJson.msg =
                    '데이터를 확인하던 중 오류가 발생하였습니다. _FAQ_LIST_Error: ' + `${stamp}`;
                resJson.result = [error.message];

                conn.release();
            }
        } else {
            console.log(
                '_INJECTION  /  ip: ' +
                    ip +
                    '  /  option: ' +
                    option +
                    '  /  nowPage: ' +
                    nowPage +
                    '  /  ' +
                    date
            );
            resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        }
        res.send(resJson);
    }
});

app.post('/faqRead', async (req, res) => {
    let sessionID = req.body.sessionID;
    let option = req.body.variable1;
    let seq = req.body.variable2;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;
    if (option == 'private') {
        if (nInjectionCheck(sessionID) && nInjectionCheck(option) && nInjectionCheck(seq)) {
            try {
                const query1 = 'SELECT * FROM sessions_table WHERE user_session = ?';

                conn = await mysql.getConnection();

                const [result] = await conn.query(query1, sessionID);

                if (result.length <= 0) {
                    conn.release();
                    resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                    res.send(resJson);
                    return;
                }

                const query2 =
                    'SELECT * FROM faqs_table WHERE seq=? AND faq_option=? AND faq_from_whom=?';

                const [result2] = await conn.query(query2, [
                    seq,
                    option,
                    result[0].user_session_address,
                ]);

                const query3 =
                    'SELECT * FROM answers_table WHERE seq=? AND answer_option=? AND answer_to_whom=?';

                const [result3] = await conn.query(query3, [
                    seq,
                    option,
                    result[0].user_session_address,
                ]);

                if (result2.length <= 0 || result3.length <= 0) {
                    resJson.msg = '존재하지 않는 문의사항 입니다.';
                } else {
                    resJson.ok = true;
                    resJson.msg = '문의사항 로딩에 성공하셨습니다.';
                    resJson.result = [result2, result3];
                }

                conn.release();
            } catch (error) {
                let stamp = date.getTime();

                console.log('_FAQ_READ_Error  /  ip: ' + ip + '  /  ' + stamp);
                console.log(error);

                resJson.msg =
                    '데이터를 확인하던 중 오류가 발생하였습니다. _FAQ_READ_Error: ' + `${stamp}`;
                resJson.result = [error.message];

                conn.release();
            }
        } else {
            console.log(
                '_INJECTION  /  ip: ' +
                    ip +
                    '  /  session: ' +
                    `${sessionID}` +
                    '  /  option: ' +
                    option +
                    '  /  seq: ' +
                    seq +
                    '  /  ' +
                    date
            );
            resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        }
        res.send(resJson);
    } else {
        if (nInjectionCheck(option) && nInjectionCheck(seq)) {
            try {
                conn = await mysql.getConnection();

                const query1 = 'SELECT * FROM faqs_table WHERE seq=? AND faq_option=?';

                const [result] = await conn.query(query1, [seq, option]);

                const query2 = 'SELECT * FROM answers_table WHERE seq=? AND answer_option=?';

                const [result2] = await conn.query(query2, [seq, option]);

                if (result.length <= 0 || result2.length <= 0) {
                    resJson.msg = '존재하지 않는 문의사항 입니다.';
                } else {
                    resJson.ok = true;
                    resJson.msg = '문의사항 로딩에 성공하셨습니다.';
                    resJson.result = [result, result2];
                }

                conn.release();
            } catch (error) {
                let stamp = date.getTime();

                console.log('_FAQ_READ_Error  /  ip: ' + ip + '  /  ' + stamp);
                console.log(error);

                resJson.msg =
                    '데이터를 확인하던 중 오류가 발생하였습니다. _FAQ_READ_Error: ' + `${stamp}`;
                resJson.result = [error.message];

                conn.release();
            }
        } else {
            console.log(
                '_INJECTION  /  ip: ' +
                    ip +
                    '  /  option: ' +
                    option +
                    '  /  seq: ' +
                    seq +
                    '  /  ' +
                    date
            );
            resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
        }
        res.send(resJson);
    }
});

app.post('/faqWrite', async (req, res) => {
    let sessionID = req.body.sessionID;
    let option = req.body.variable1;
    let title = req.body.variable2;
    let main = req.body.variable3;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;
    if (option == 'private') {
        if (
            nInjectionCheck(sessionID) &&
            nInjectionCheck(option) &&
            tInjectionCheck(title) &&
            tInjectionCheck(main)
        ) {
            try {
                const query1 = 'SELECT * FROM sessions_table WHERE user_session = ?';

                conn = await mysql.getConnection();

                const [result] = await conn.query(query1, sessionID);

                if (result.length <= 0) {
                    conn.release();
                    resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                    res.send(resJson);
                    return;
                }

                if (title.length <= 0) {
                    conn.release();
                    resJson.msg = '제목을 작성하여 주십시오.';
                    res.send(resJson);
                    return;
                }

                if (title.length > 100) {
                    conn.release();
                    resJson.msg = '제목은 100자 이내로 작성하셔야 합니다.';
                    res.send(resJson);
                    return;
                }

                if (main.length <= 0) {
                    conn.release();
                    resJson.msg = '본문을 작성하여 주십시오.';
                    res.send(resJson);
                    return;
                }

                if (main.length > 500) {
                    conn.release();
                    resJson.msg = '본문은 500자 이내로 작성하셔야 합니다.';
                    res.send(resJson);
                    return;
                }

                const query2 =
                    'INSERT INTO faqs_table(faq_process, faq_option, faq_from_whom, faq_title, faq_main, faq_created_at, faq_updated_at) VALUES("요청완료", ?, ?, ?, ?, now(), now())';

                const [result2] = await conn.query(query2, [
                    option,
                    result[0].user_session_address,
                    title,
                    main,
                ]);

                const query3 =
                    'INSERT INTO answers_table(answer_option, answer_to_whom, answer_title, answer_main, answer_created_at, answer_updated_at) VALUES(?, ?, ?, ?, now(), now())';

                const [result3] = await conn.query(query3, [
                    option,
                    result[0].user_session_address,
                    null,
                    null,
                ]);

                resJson.ok = true;
                resJson.msg = '문의사항 작성에 성공하셨습니다.';

                conn.release();
            } catch (error) {
                let stamp = date.getTime();

                console.log('_FAQ_WRITE_Error  /  ip: ' + ip + '  /  ' + stamp);
                console.log(error);

                resJson.msg =
                    '데이터를 확인하던 중 오류가 발생하였습니다. _FAQ_WRITE_Error: ' + `${stamp}`;
                resJson.result = [error.message];

                conn.release();
            }
        } else {
            console.log(
                '_INJECTION  /  ip: ' +
                    ip +
                    '  /  session: ' +
                    `${sessionID}` +
                    '  /  option: ' +
                    option +
                    '  /  ' +
                    date
            );
            resJson.msg = '영문, 한글, 숫자, !, ?, @, 온점, 쉼표만 작성하실 수 있습니다.';
        }
        res.send(resJson);
    } else {
        if (nInjectionCheck(option) && tInjectionCheck(title) && tInjectionCheck(main)) {
            try {
                conn = await mysql.getConnection();

                if (title.length <= 0) {
                    conn.release();
                    resJson.msg = '제목을 작성하여 주십시오.';
                    res.send(resJson);
                    return;
                }

                if (title.length > 100) {
                    conn.release();
                    resJson.msg = '제목은 100자 이내로 작성하셔야 합니다.';
                    res.send(resJson);
                    return;
                }

                if (main.length <= 0) {
                    conn.release();
                    resJson.msg = '본문을 작성하여 주십시오.';
                    res.send(resJson);
                    return;
                }

                if (main.length > 500) {
                    conn.release();
                    resJson.msg = '본문은 500자 이내로 작성하셔야 합니다.';
                    res.send(resJson);
                    return;
                }

                const query1 =
                    'INSERT INTO faqs_table(faq_process, faq_option, faq_from_whom, faq_title, faq_main, faq_created_at, faq_updated_at) VALUES("요청완료", ?, ?, ?, ?, now(), now())';

                const [result] = await conn.query(query1, [option, ip, title, main]);

                const query2 =
                    'INSERT INTO answers_table(answer_option, answer_to_whom, answer_title, answer_main, answer_created_at, answer_updated_at) VALUES(?, ?, ?, ?, now(), now())';

                const [result2] = await conn.query(query2, [option, ip, null, null]);

                resJson.ok = true;
                resJson.msg = '문의사항 작성에 성공하셨습니다.';

                conn.release();
            } catch (error) {
                let stamp = date.getTime();

                console.log('_FAQ_WRITE_Error  /  ip: ' + ip + '  /  ' + stamp);
                console.log(error);

                resJson.msg =
                    '데이터를 확인하던 중 오류가 발생하였습니다. _FAQ_WRITE_Error: ' + `${stamp}`;
                resJson.result = [error.message];

                conn.release();
            }
        } else {
            console.log('_INJECTION  /  ip: ' + ip + '  /  option: ' + option + '  /  ' + date);
            resJson.msg = '영문, 한글, 숫자, !, ?, @, 온점, 쉼표만 작성하실 수 있습니다.';
        }
        res.send(resJson);
    }
});

app.post('/supportRead', async (req, res) => {
    let sessionID = req.body.sessionID;
    let option = req.body.variable1;
    let nowPage = req.body.variable2;

    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    if (nInjectionCheck(sessionID)) {
        try {
            const query1 = 'SELECT * FROM sessions_table WHERE user_session = ?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, sessionID);

            if (result.length <= 0) {
                conn.release();
                resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                res.send(resJson);
                return;
            }
            
            let query2, who;
            
            if(option == 'request'){
                query2 = 'SELECT COUNT(*) as cnt FROM supports_table WHERE support_writer=?';
                who = result[0].user_session_address;
            }
            else{
                query2 = 'SELECT COUNT(*) as FROM supports_table WHERE support_supporters Like ?';
                who = '%'+result[0].user_session_address+'/'+'%';
            }
            
            const [result2] = await conn.query(query2, [who]);
            
            let supportNum = result2[0].cnt;
            let startSupportNum = 20 * (nowPage - 1);
            let limitSupportNum = supportNum >= startSupportNum + 20 ? 20 : supportNum - startSupportNum;
            
            let query3;
            
            if(option == 'request'){
                query3 = 'SELECT * FROM supports_table WHERE support_writer=? ORDER BY seq DESC Limit ?, ?';
            }
            else{
                query3 = 'SELECT * FROM supports_table WHERE support_supporters LIKE ? ORDER BY seq DESC Limit ?, ?';
            }
            
            const [result3] = await conn.query(query3, [who, startSupportNum, limitSupportNum]);
            
            resJson.ok = true;
            resJson.msg = '후원목록 로딩에 성공하셨습니다.';
            resJson.result = [supportNum, result3];
            
            conn.release();
        } catch (error) {
            let stamp = date.getTime();

            console.log('_SUPPORT_READ_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SUPPORT_READ_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        console.log(
            '_SESSION_INJECTION  /  ip: ' + ip + '  /  session: ' + `${sessionID}` + '  /  ' + date
        );
        resJson.msg = '세션에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
    }
    res.send(resJson);
});

app.post('/supportWrite', async (req, res) => {
    let sessionID = req.body.sessionID;
    let infos = req.body.variable1;
    infos = infos.split('&%!,');
    let images = req.body.variable2;
    images = images.split('&%!,');
    let main = req.body.variable3;
    
    console.log(infos[0]);
    console.log(images[0]);
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;

    let injection = () => {
        if (!nInjectionCheck(sessionID)) {
            return false;
        }
        for (let i = 0; i <= 3; i++) {
            if (!tInjectionCheck(infos[i])) {
                return false;
            }
        }
        for (let i = 0; i <= 5; i++) {
            if (!nInjectionCheck(images[i])) {
                return false;
            }
        }
        if (!tInjectionCheck(main)) {
            return false;
        }
        return true;
    };

    if (injection) {
        try {
            const query1 = 'SELECT * FROM sessions_table WHERE user_session = ?';

            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, sessionID);

            if (result.length <= 0) {
                conn.release();
                resJson.msg = '만료된 세션입니다. 다시 로그인 해 주십시오.';
                res.send(resJson);
                return;
            }
            if (infos[0].length <= 0) {
                conn.release();
                resJson.msg = '제목을 작성하여 주십시오.';
                res.send(resJson);
                return;
            }
            if (infos[0].length > 100) {
                conn.release();
                resJson.msg = '제목은 100자 이내로 작성하셔야 합니다.';
                res.send(resJson);
                return;
            }
            if (infos[1].length <= 0) {
                conn.release();
                resJson.msg = '제품명을 작성하여 주십시오.';
                res.send(resJson);
                return;
            }
            if (infos[1].length > 50) {
                conn.release();
                resJson.msg = '제품명은 50자 이내로 작성하셔야 합니다.';
                res.send(resJson);
                return;
            }
            if (infos[2].length <= 0) {
                conn.release();
                resJson.msg = '가격을 작성하여 주십시오.';
                res.send(resJson);
                return;
            }
            if (infos[2].length > 16) {
                conn.release();
                resJson.msg = '가격은 9999조원을 초과할 수 없습니다.';
                res.send(resJson);
                return;
            }
            if (infos[2] < 0) {
                conn.release();
                resJson.msg = '가격은 음수일 수 없습니다.';
                res.send(resJson);
                return;
            }
            if (infos[3].length <= 0) {
                conn.release();
                resJson.msg = '목표를 작성하여 주십시오.';
                res.send(resJson);
                return;
            }
            if (infos[3].length > 16) {
                conn.release();
                resJson.msg = '목표는 9999조개를 초과할 수 없습니다.';
                res.send(resJson);
                return;
            }
            if (infos[3] <= 0) {
                conn.release();
                resJson.msg = '목표 인원수는 최소 1명이어야 합니다.';
                res.send(resJson);
                return;
            }
            if (main.length <= 0) {
                conn.release();
                resJson.msg = '본문을 작성하여 주십시오.';
                res.send(resJson);
                return;
            }
            if (main.length >= 5000) {
                conn.release();
                resJson.msg = '본문의 길이가 너무 깁니다.';
                res.send(resJson);
                return;
            }
            let imageAddress = [];
            for(let i=0; i<images.length; i++){
                let firstSplit = images[i].split(',');
                let secondSplit = firstSplit[0].split('/');
                let lastSplit = secondSplit[1].split(';');
                
                const fileData = {
                    data: firstSplit[1],
                    extender: `.${lastSplit[0]}`
                };
                
                if(images[0] == (
                `iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBl
                SsOGwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAABS+SURBVHic7d15zGZVfQfw74wwgDJsgoA
                ICqIoiIIooLghuGKVaCM0rZKIMTVqjW1SrdVoW1P3paRVG6uNW9UuSi1L64KAiEUWqRuLLCIiIiDbsM3aP85MBGTmP
                fd5733ufe7z+SQnIZnznPu7hzzv/T3nniUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgQ0v6DgDm1K5JDk+ye9+B9
                OzqJKcl+VXfgQBA196e5I4k65SsS3J7kr9cVI8CwMD9Vfp/4A61vGMR/QoAg/XwJHel/wftUMudSfaYuHeBRpb2HQD
                MkeOTbNF3EAO2ZZJX9R0EALTtJ+n/V/bQy8UT9y4ADNCB6f/hOivlgAn7GGhgs74DgAa2S7JDh+1flzIjvQvHdNTuG
                B2T5MK+gwCgf4ckOTPJmnT7y3NlkhOT7N1y/EuSXNFx7GMql8ceJQBz74VJ7s50H0C/SbJ/i/dwyJTjH0M5eKKeBqp
                5BcCQbZPk00mWTfm62yf5TJKDkqxtob3a4f/bk/x9C9cbstcneVBFvWOTfK/jWAAYqOPS76/QQ1u4h6VJflF5vS+2c
                L2h+2Lq+uLqWKYMnfIFY8j2G8H1n5Zkt8q6X2rhekNXe48PS3JYl4HAvJMAMGRb9nz9B7bQxrGV9W5NcmoL1xu6U5L
                cUlnXygnokAQAuvOAJC+trHtiyjbBY3d3kq9W1n15zFOCzkgAoDtHJNm5su48DP9vUHuvOyV5VodxwFyTAEB3aoewb
                0ryjS4DGZivJbmxsq7XANARw2uMwQ0p79Br7ZiyxLBLy5IcXVn3P1I2IZoXq5J8JcmrK+q+NMnrMl/9AzD3TkjdkrE
                3DKTde3pR5TXWpbwqmDdHpr5/juopRhg1rwCgG7VD19cnOaPLQAbqWylnL9TwGgA6IAGA9m2Z5MWVdf81yeoOYxmqN
                SmvPmocnWSrDmOBuSQBgPYdlfo5BvM0+/++au99eZIXdBkIzCOTAOnalkmem2SfNE84D6qsd2SabdrTVbsbvKSy3jV
                JvjNB+2NxVkof1OyUeEySL7dwzWUpcy4em2TzFtrrwtokl6SslpiHvSGAETo8ZU/3vk+WG2r58ORdOxofTl1f3Z5k6
                0Ve65CUo4b7/v9eW34e+yAAM+hJSe5M/39Eh1zaOGxo1h2a+v76g0VcZ88kNze41lDKHUmeuIj7Bpi6M9P/H88hlyu
                TLJm4d8djSUpf1PTZiYu4zicqrzHEcvoi7htgqnZKeY/Z9x/OIZf3Tty74/Pe1PXZrSnnK0yi9kjmIZa1SR484X3DR
                lkFQBd2i1+3C5nn2f/31WQ1wA4TXqP2TIYhWpJyPDK0SgJAFyb9lTYvLk1yQd9BDMgFKX2ykJVptuXzPdVuOjRUVmz
                ROgkATN9H+w5ggD5ZUefUlOOEJ3HqhJ8DoIGD0v9706GWC5NsMXnXjtbylFGAjfXbjUn2XkT7s7oKYEOp3bsCqhkBg
                Ok5NWUTmkl/xY7ZbSkbRp13P/92bpJnJLlsEe1fmeR5Sa5YRBswKt4r0adrk3ym7yA6tjbJVUm+l+T7PccydD9L2az
                nGUmekHJGwnlJzmmp/XNSdgB8dpJ9kzykpXYX47gku/QdBEBbal8BtPWHHWbVefEKgJ54BQAAc8grAJgvW6UccLRty
                vd/Xco++ysy+RI7YAZJAGCc9k5yYMq79McleXjKZjI7LvC5m1Imyl2S5KKUmfnnpMxjAEZEAgDj8OAkR6UcYXxkkl0
                nbGf7lPfN933nfEWS05J8K8n/pCzLA4B7MQlwOrZO8sokp6TskjetNel3pxzM89LY02CxTAIERkUC0K09k3wgZbi+7
                w1qblwfy0M7vePxkgAAoyIB6MbeST6XZE36f/Dft9yVssXxI7q6+ZGSAACjIgFo10OS/GOmO8w/aVmZ5ISUVQYsTAJ
                Ab+wDAMO1JOUd/4+TvCbJ5v2GU2XzJG9IcnFK7I6FhoGSAMAwPSLJmUk+nYWX7g3RLimxfz3OsodBkgDA8Px+kguSP
                K3vQFpwRMoZCC/sOxDg3iQAMBybJ/lYkn9LWY/fletT1vVfmuT89f99Y8rhO13YMclJSd4Te4/AYPgywjBsn/LgP6L
                FNq9NclbKZMsfpbyXvyYbf9BvlmSPJHslOSDJwSmjEJNuKnRPS5K8OWVXwpcnuaOFNgEYGKsAmtktyU/Sziz8C5K8N
                eW42zYsSUkG3pqSRLQR49lJdmgpvllnFQAwKhKAenskuSyLe6DenvLq4IlTiPdJST6Rsu5/MTH/OCYHJhIAYGQkAHV
                2T/KzTP4QXZHkvSn7BEzbLknelzKUP2n8P0k5w2CeSQCAUZEALGy7TD6kvjbJZ1NeHfRtj5TdCddmsnv5bsrxxPNKA
                gCMigRg07ZIcnome2BemeRZ0w64wnMz+WjGyZmNTY66IAEARkUCsGkfz2QPys8k2aaHeGstT/LFTHZv7+8h3iGQAAC
                jIgHYuFek+cNxZcr2urPiDUlWpdk9rk3yoj6C7ZkEABgVCcD9e0zKjP0mD8YVKcPrs+aolNib3OsNKRMj54kEABgVC
                cDvWpqy/r3JA/E3SZ7SR7AtOTTJLWl2z2dkvg4QkgAAoyIB+F1vSrMH4e3p9iyA5Skb/Dw5ZdOgNnb7uz9PSXJrmt3
                7cR3FMkQSAGBUJAD39tA0Gw6/O8mRHcXy4JRT+u5vI59bk5yb5MNJfi/JVi1d83lpNifgunR7FsKQSACAUZEA3Nun0
                uwX8Gs7iuNBSX7QII5bknwy7eww+CcNrrsuyT+0cM1ZIAEARkUC8Fv7pxy+U/vg+1SHsbyjQRz3LackOXCR1/9cg+u
                tTrL3Iq83CyQAwKhIAH7ry6l/6F2W8iu9Kxc1iGVjD+UTUuYPTGKbJJc3uN4/TXidWSIBAEZFAlA8Osma1PXFmiSHd
                RzPyspYFioXJ3n8hDE8M/XbBt+dstXwmEkA6M3SvgOAEfvT1H/H/jnJdzqMJSkrC9qwT5L/TfLiCT57RsqOhjWWJfn
                zCa4BQE+MACTbpn7Tn1uS7DyFmE6qjKe2rEryygni2Dn1qyJuzbgPCzICQG+MAEA3Xp76B9eHUpa+de39KcPvbdksZ
                dLiSxp+7rqUuQQ1lic5umH7APTECEByVup//U9zzfsk+/QvVO5I8xUCOyS5rbL9Uye50RlhBAAYlXlPAB6e+oluH+w
                hvv1SRgNOTnJhkmsbxLux8tM0P6nwo5Vtr053OxX2TQIAjMq8JwCvTd39r02ZUDcEWyR5fspRxTdksiTg4w2vuW+Dt
                o+f+M6GTQIAjMq8JwBfTd39n9lXgAvYNsnfpvnJhWuSHNLwWudWtv35xdzQgEkA6I1JgNCuzZM8u7Luv3cZyCLckuS
                tSZ6QsnlQraVJ3t3wWl+orHd45uuUQICZNM8jAAemfvh/Fja52S7JaWk2EvDUBu0/skG7+y76bobHCAC9MQIA7XpyZ
                b1Lkvy8y0BacnPKMr8fN/jM6xvUvTzJlZV1D23QLrAACQC0qzYBOKvTKNp1W8pa/Nsq6x+dZisCTqus95gGbQILkAB
                Aux5VWe+7nUbRvsuSfKCy7lZJXtig7Qsq6w1lxQSMggQA2rVnZb0mQ+pD8aEkv6qse0SDdi+srCcBgBZJAKA9y5LsV
                lm3yez6oViR5F8q6z69QbuXVtbbK/5mQWt8maA9OyZ5QEW9m1IOuZlFJ1bWe2TKksgaN6RsJ7yQzZNsXdkmsAAJALR
                n28p613caRbfOTt2xwpul/nVIUrYjrtF0u2FgIyQA0J7aBOA3nUbRrTVJrqmsu2ODdldU1pMAQEskANCeLSrrreo0i
                u7VJgBNHtY1rwCScjww0AIJALRnTWW91Z1G0b3a4fra/miiZo4FUEECAO2pfbBv1WkU3bu4os66ynob1I4W1I4UAAu
                QAEB77qqsVztXYKg+n2TlAnW+meTqBm3WDu3f2aBNYBMkANCe2tn9TSbHDdEVSd6Y8iv//vwyyWsatlmbFM3q8kkYH
                AkAtOe6bPyheE87ZfbXs388yZEpv/Q3jAZcn+RjKSci1h7wk5T+qEkAViX5dYN2gU3YrO8AYERWJ7kxdb/w90ryg27
                D6dxp68vSJA9M/VK++6rd4veX6WZiIcwlIwDQrksq6z2+0yima20mf/gn9QnALByfDDNDAgDtqt3j/+BOo5gttX3xw
                06jgDkjAYB21Z7yd1inUcyWwyvr/V+nUcCckQBAu86prHdgkl26DGRG7JHkUZV1a48NBipIAKBd56dus5olSV7QcSy
                zoLYPVkQCAK2SAEC7Vib5XmXdY7sMZEb8UWW9M7Pw5kNAAxIAaN8plfWOTLJ7l4EM3CNSPxfiGx3GAXNJAgDtO7Gy3
                tIkr+oykIF7dcqrkBr/1WUgALTjoJQd8RYqtRPmZtEPU9cHv87sHw40iW2S3JS6Pqp9pTKLzktdHxzUV4CMlxEA6MZ
                nK+vtlOT4LgMZqNcl2a6y7he6DASA9hgBSHZOmbRW0w/Xpf40vDHYLmXko6Zv7krpy7EyAkBvjABAN65L8p+VdR+S5
                C0dxjI070oZ+ajxpZS+BGAGGAEoDkldP6xLcneSx/UT5lQ9MeXQpNp+eVI/YU6NEQB6YwQAunNOynG5NZYl+WSSB3Q
                XTu+2TLN7/FrKAxLogAQAuvWuBnUPTvI3XQUyAB9KckBl3XVJ3tZhLAB0wCuAezsp9UPea5O8qJ8wO3VM6vtgXZKv9
                BPm1HkFAIyKBODeHpkym7324XdrymFBY3FIyl7+tfd/V5J9eol0+iQA9MYrAOje5UlOaFB/eZKTk+zZTThTtW/K1sg
                PavCZdye5pJtwAOiSEYDftVWSi9JsGPyqJHv3EWxLHpvk6jS754tTJgvOCyMA9MYIAEzHnUmOS1kCV2uPJKcn2b+Lg
                Dr2lCTfTvKwBp9ZmeQPU14BADCDjABs3NvT7BfxhjkBR/UR7IReluT2NL/PP+sj2J4ZAQBGRQKwcUtTdghs+nBcneS
                vk2w2/ZCrLUvyd2l+b+tSTlCsPRlwTCQAwKhIADZtmzSfD7ChfCfJo6cf8oL2T3JuJrunC5NsPf2QB0ECAIyKBGBhe
                ya5JpM9MO9K8s4M4xjh5Uk+mGRVJruXX6bMdZhXEgBgVCQAdfZLcmMme3CuS/KLJH+cZPNpB57kgUnemPIAnzT+X6c
                sE5xnEgBgVCQA9Z6cxSUB61KW2v1Fkh2nEO+u66913SJjviHJ46cQ79BJAIBRkQA087hM/jrgnuWulMl0x6bMM2jLD
                inL805Ns5P8NpWwzMPJhzUkAMCoSACa2zNlE5zFPlw3lFUpEwbflbIsb6/U7fuxLOXVxMuSvC/lAbWmxbh+lGT3hn0
                zZhIAejPkJUUwT65M2TP/c2nnMKDNkjx1fdlgVZJrU97br0hyR0pSsDxlFv5OSXZLd0cSn5TkFUlu7qh9AHpmBGByS
                1Nm+Lcx1D6UsirJWzKf6/wXYgSA3tgKGIZlbUoC8IwkP+03lFZckuSZSd6T8iADBkICAMN0dpIDknwkzc4PGIrVKXM
                IDki5F2BgJAAwXHckeVPKjPlTeo6liW+kDFm/OQ72gcGSAMDwXZJyGNALUmb2D9XZSY5M8pwkP+g5FmABEgCYHf+d5
                GlJDk9ycsryvL6tTfLVJE9PcliSb/YbDlDLMkCYPaevL7snOT7JK1P2EZimS5N8dn25asrXBmCgLAOcvgNSVg+cm8k
                P5tlUWZ0yxP+2WJLWJssA6Y0RABiHC9eXd6Zs6vPUJIem7Or3mCT7JNmisq3bklyRsgzxvJSk4vwkt7QaMdArCQCMz
                4okX1tf7mnHlN3+dkrZ8jdJtk9y6/pyS5Lr1xdg5CQAMD9uWF8u6jsQoH9WAQDAHJIAAMAckgAAwBySAADAHJIAAMA
                ckgAAwBySAADAHJIAAMAckgAAwByyEyB92jXJm/sOAnq0S98BML8kAPRp9yTv6TsIgHnkFQAAzCEJAADMIQkAAMwhC
                QBdWNN3ADAyq/sOgPGRANCFXyRZ13cQMBLrUr5T0CoJAF24Icm3+w4CRuKMJDf2HQTjs6TvABitg5KclWTLvgOBGXZ
                nksOSfL/vQBgfIwB05fwkz0/y874DgRl1Vcp3yMOfThgBoGtbJnlOkv2SbNdzLDALbk7yoyRfT3J3z7EAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAk/l/3fIEQ1IedkUAAAAASUVORK5CYII=`
                )){
                    fileData.data = null;
                }
                
                const [state, msg] = await UploadImage(fileData);
                
                if(state == false){
                    conn.release();
                    resJson.msg = '사진을 저장하던 중 오류가 발생하였습니다.';
                    res.send(resJson);
                    return;
                }
                else{
                    imageAddress.add(msg);
                }
            }
            
            const query2 =
                'INSERT INTO supports_table(support_writer, support_title, support_product, support_price, support_goal, support_images, support_main) VALUES(?, ?, ?, ?, ?, ?, ?)';

            const [result2] = await conn.query(query2, [
                result[0].user_session_address,
                infos[0],
                infos[1],
                infos[2],
                infos[3],
                imageAddress,
                main,
            ]);

            resJson.ok = true;
            resJson.msg = '후원 요청에 성공하셨습니다.';

            conn.release();
        } catch (error) {
            let stamp = date.getTime();

            console.log('_SUPPORT_WRITE_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SUPPORT_WRITE_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    } else {
        console.log('_INJECTION  /  ip: ' + ip +  '  /  ' + date);
        resJson.msg = '영문, 한글, 숫자, !, ?, @, 온점, 쉼표만 작성하실 수 있습니다.';
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

const regexE = /[^a-zA-Z0-9!\?@\.]/;
const regexP = /[^a-zA-Z0-9!\?@]/;
const regexN = /[^a-zA-Z0-9가-힣]/;
const regexT = /[^a-zA-Z0-9ㄱ-ㅎㅏ-ㅣ가-힣!\?@\.,\s]/;

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

function tInjectionCheck(t) {
    if (t.match(regexT)) {
        return false;
    } else {
        return true;
    }
}

const smtpTransport = nodeMailer.createTransport({
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

const generateRandomNumber = (min, max) => {
    let randNum = Math.floor(Math.random() * (max - min + 1)) + min;

    return randNum;
};

const emailAuthorize = (req, res, resJson) => {
    const number = generateRandomNumber(111111, 999999);

    const mail = req.body.email;

    const mailOptions = {
        from: process.env.AUTH_EMAIL_ADDRESS,
        to: mail,
        subject: 'Softhub 인증메일',
        html: '<h1>인증번호를 입력해주세요<h1><br>' + number,
    };

    smtpTransport.sendMail(mailOptions, (error, response) => {
        console.log('response: ' + response);
        let date = new Date();
        let ip = requestIp.getClientIp(req);
        if (error) {
            let stamp = date.getTime();
            console.log(
                '_SEND_EMAIL_Error  /  ip: ' + ip + '  /  email: ' + mail + '  /  ' + stamp
            );
            console.log(error);
            resJson.msg = '인증메일 전송에 실패하였습니다. _SEND_EMAIL_Error: ' + `${stamp}`;
            resJson.result = [error.message];
            res.send(resJson);
            smtpTransport.close();
        } else {
            console.log(
                '_SEND_EMAIL_Success  /  ip: ' + ip + '  /  email: ' + mail + '  /  ' + date
            );
            resJson.ok = true;
            resJson.msg = `${mail}` + ' 으로 인증메일 전송에 성공하였습니다.';
            resJson.result = [number];
            res.send(resJson);
            smtpTransport.close();
        }
    });
};

async function makeSession(conn, req, res, resJson) {
    let address = req.body.email;
    let date = new Date();
    let ip = requestIp.getClientIp(req);
    try {
        const query1 =
            'SELECT seq FROM sessions_table WHERE DATE_FORMAT(DATE_ADD(session_created_at, INTERVAL ? day), "%Y%m%d%H") <= DATE_FORMAT(now(), "%Y%m%d%H")';

        const [result] = await conn.query(query1, MaxAge);

        if (result.length >= 1) {
            let target = '';
            let array = [];
            for (var i = 0; i < result.length; i++) {
                target += '?';
                array.push(result[i].seq);
                if (!(i >= result.length - 1)) {
                    target += ',';
                }
            }
            const query2 = 'DELETE FROM sessions_table WHERE seq in(' + target + ')';

            const [result2] = await conn.query(query2, array);
        }

        const salt2 = crypto.randomBytes(128).toString('base64');
        const param = Math.floor(Math.random() * (999999 - 111111 + 1)) + 111111;
        const session = hashing(salt2, param);

        const query3 = 'SELECT * FROM sessions_table WHERE user_session = ?';

        const [result3] = await conn.query(query3, session);

        if (result3.length >= 1) {
            makeSession(conn, address, res, resJson);
            return;
        }

        const query4 = 'SELECT * FROM sessions_table WHERE user_session_address = ?';

        const [result4] = await conn.query(query4, address);

        if (result4.length >= 1) {
            const query5 =
                'UPDATE sessions_table SET user_session=?, session_created_at=now() WHERE user_session_address=?';

            const [result5] = await conn.query(query5, [session, address]);

            resJson.result = [session, MaxAge];

            res.send(resJson);

            return;
        } else {
            const query6 =
                'INSERT INTO sessions_table(user_session, user_session_address, session_created_at) VALUES(?, ?, now())';

            const [result6] = await conn.query(query6, [session, address]);

            resJson.result = [session, MaxAge];

            res.send(resJson);

            return;
        }
    } catch (error) {
        let stamp = date.getTime();
        console.log(
            '_MAKE_SESSION_Error  /  ip: ' + ip + '  /  email: ' + address + '  /  ' + stamp
        );
        console.log(error);
        resJson.ok = false;
        resJson.msg =
            '데이터를 확인하던 중 오류가 발생하였습니다. _MAKE_SESSION_Error: ' + `${stamp}`;
        resJson.result = [error.message];
        res.send(resJson);
        return;
    }
}

async function UploadImage(fileData){
    let date = new Date();
    const storage = new Storage({
        projectId: process.env.PROJECT_ID,
        credentials: {
          client_email: process.env.CLIENT_EMAIL,
          private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
        },
    });
    console.log(process.env.PRIVATE_KEY.replace(/\\n/g, "\n"));
    
    if(fileData.data == null){
        return [null, 'null'];
    }
    else{
        let imageName = `${date.getTime()}`+`${fileData.extender}`;
        let fileName = './imageFolder/'+imageName;
        !fs.existsSync('./imageFolder') && fs.mkdirSync('./imageFolder');
        
        await fs.writeFileSync(fileName, fileData.data, 'base64');
        
        const uploading = async() => { 
            storage.bucket(process.env.BUCKET_NAME).upload(fileName, {
                destination: imageName,
            });
        };
        
        uploading().catch((error) => {return ['false', error.message];});
        uploading().then(() => {return ['true', imageName];});
    }
}