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

app.post('/supportList', async (req, res) => {
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
                query2 = 'SELECT COUNT(*) as cnt FROM supports_table WHERE support_supporters Like ?';
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

            console.log('_SUPPORT_LIST_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SUPPORT_LIST_Error: ' + `${stamp}`;
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

app.post('/supportRead', async(req, res) => {
    let sessionID = req.body.sessionID;
    let seq = req.body.variable1;
    
    let date = new Date();
    let ip = requestIp.getClientIp(req);

    let resJson = {
        ok: false,
        msg: '',
        result: null,
    };
    let conn = null;
    
    if(nInjectionCheck(seq)){
        try{
            const query1 = 'SELECT * FROM supports_table WHERE seq = ?';
            
            conn = await mysql.getConnection();

            const [result] = await conn.query(query1, seq);
            
            if(result.length <= 0){
                conn.release();
                resJson.msg = '존재하지 않는 후원글 입니다.';
                res.send(resJson);
                return;
            }
            
            let user_session_address = null;
            if(sessionID != 'undefined'){
                if(nInjectionCheck(sessionID)){
                    const query2 = 'SELECT * FROM sessions_table WHERE user_session = ?';
                
                    const [result2] = await conn.query(query2, sessionID);
                
                    if(result2.length <= 0){
                        conn.release();
                        resJson.msg = '만료된 세션입니다 다시 로그인 해 주십시오.';
                        res.send(resJson);
                        return;
                    }
                    user_session_address = result2[0].user_session_address;
                }
                else{
                    console.log(
                        '_SESSION_INJECTION  /  ip: ' + ip + '  /  session: ' + sessionID + '  /  ' + date
                    );
                    conn.release();
                    resJson.msg = '세션에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
                    res.send(resJson);
                    return;
                }
            }
            
            let isSame = false;
            if(user_session_address != result[0].support_writer){
                isSame = false;
            }
            else if(user_session_address == result[0].support_writer){
                isSame = true;
            }
            else{
                isSame = false;
            }
            
            resJson.ok = true;
            resJson.msg = '후원글 로딩에 성공하셨습니다.';
            resJson.result = [result, isSame];
            
            conn.release();
        }
        catch(error){
            let stamp = date.getTime();

            console.log('_SUPPORT_READ_Error  /  ip: ' + ip + '  /  ' + stamp);
            console.log(error);

            resJson.msg =
                '데이터를 확인하던 중 오류가 발생하였습니다. _SUPPORT_READ_Error: ' + `${stamp}`;
            resJson.result = [error.message];

            conn.release();
        }
    }
    else{
        console.log(
            '_INJECTION  /  ip: ' + ip + '  /  seq: ' + seq + '  /  ' + date
        );
        resJson.msg = '요청에 적절하지 않은 문자가 포함되어 있습니다. 서버에 ip가 저장됩니다.';
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
            
            const query3 = 'SELECT * FROM users_table WHERE user_address = ?';
            
            const [result3] = await conn.query(query3, result[0].user_session_address);
            
            if(result3.length <= 0){
                conn.release();
                resJson.msg = '존재하지 않는 계정에 대한 세션입니다. 다시 로그인 해 주십시오.';
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
            let imageAddress = '';
            for(let i=0; i<6; i++){
                let fileData;
                console.log(images[i]);
                console.log(images[i] !== 'null');
                if(images[i] !== 'null'){
                    let firstSplit = images[i].split(',');
                    let secondSplit = firstSplit[0].split('/');
                    let lastSplit = secondSplit[1].split(';');
                
                    fileData = {
                        data: firstSplit[1],
                        extender: `.${lastSplit[0]}`
                    };
                }
                else{
                    fileData = {
                        data: null,
                        extender: null,
                    };
                }
                
                const [state, msg] = await UploadImage(fileData);
                
                if(state == false){
                    conn.release();
                    resJson.msg = '사진을 저장하던 중 오류가 발생하였습니다.';
                    res.send(resJson);
                    return;
                }
                else{
                    imageAddress += msg+'&%!,';
                }
            }
            
            const query2 =
                'INSERT INTO supports_table(support_writer, support_writer_id ,support_title, support_product, support_price, support_goal, support_images, support_main) VALUES(?, ?, ?, ?, ?, ?, ?, ?)';

            const [result2] = await conn.query(query2, [
                result[0].user_session_address,
                result3[0].user_id,
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
        let result = [];
        await uploading().catch((error) => {result = [false, error.message];});
        await uploading().then(() => {result = [true, imageName];});
        
        return result;
    }
}