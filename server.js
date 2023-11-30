const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const salt = 10;


dotenv.config({ path: './.env' });
const publicDirectory = path.join(__dirname,)

const app = express();
app.use(express.json());

app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET"],
    credentials:true
}));

app.use(cookieParser())

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

const verifyUser = (req,res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not auth" })
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.json({ Error: "Token in not correct" })
            } else {
                req.name = decoded.name;
                next();
            }
        })
    }
}

app.get('/',verifyUser, (req, res) => {
    return res.json({Status: "Success", Name: req.name});
});


app.post('/register', (req, res) => {

    const sql = "INSERT INTO users (`email`, `password` ) VALUES (?,?)";

    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {

        if (err) {
            return res.json({ Error: "Error for hasing psw" })
        };

        const values = [
            req.body.email,
            hash
        ]

        db.query(sql, values, (err, result) => {

            console.log("carichiamo dati in sql");
            if (err) {
                console.log(err);
                return res.json({ Error: "inserting data Errorr in server" })
            }
            console.log("passato");
            return res.json({ Status: "Success" });
        })
    })
})

app.post('/login', (req, res) => {
    
    const sql = 'SELECT * FROM users WHERE email = ?';
    
    db.query(sql, [req.body.email], (err,data) => {

        if (err) {
            return res.json({ Error: "Login error in server" });
        }

        if (data.length > 0) {

            bcrypt.compare(req.body.password.toString(), data[0].password, (err,response) => {


                if (err) {
                    return res.json({Error: "Password compare error"})
                }
                

                if (response) {
                    const name = data[0].email;
                    const token = jwt.sign({name}, "jwt-secret-key", {expiresIn: '1d'});
                    res.cookie('token', token)
                    return res.json({Status: "Success"})

                } else {

                    return res.json({Error: "Psw not matched"})

                }
            })
        } else {
            return res.json({ Error: "No email Existed" });
        }
    })
})

app.get('/logout',(req,res) => {
    res.clearCookie('token');
    return res.json({Status: "Success"});
})


app.listen(8000, () => {
    console.log("listening");
});

