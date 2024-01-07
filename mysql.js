const mysql = require('mysql2/promise');

require('dotenv').config();

module.export = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PW,
    database: process.env.DB_NAME,
    connectTimeout: 5000,
    connectionLimit: 30
});