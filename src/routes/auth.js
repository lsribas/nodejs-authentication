const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../database/user');
const { secret } = require('../config/auth.json');
const mailer = require('../modules/mailer.js');

const router = express.Router();

function generateToken(params, time) {
    return jwt.sign(params, secret, {
        expiresIn: time,
    });
};

function sendEmail(param) {
    return new Promise(resolve => {
        mailer.sendMail(param, function(err, info) {
            if(err) return resolve(err);
            resolve(info);
        })
    });
};

function containKeys(obj, arr) {
    return new Promise(resolve => {
        let array = [];
        for(const str of arr){
            if(Object.keys(obj).includes(str)){
                continue;
            }else{
                array.push(str);
            }
        }
        resolve(array);
    })
 };

router.post('/login', async function (req, res) {
    const { identification, password } = req.body;

    const contains = await containKeys(req.body, ['identification', 'password']);

    if(contains.length > 0) {
        return res.status(400).json({
            status: "Bad Request",
            message: `Parameters [${contains.join(', ')}] are missing.`
        })
    }

    if(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(identification)) {
        user = await User.findOne({ email: identification }).select('+password');

        if(!user) {
            return res.status(401).json({
                status: "Unauthorized",
                message: "Username or password is incorrect."
            })
        }

        email = user.email;
    } else {
        user = await User.findOne({ username: identification }).select('+password');

        if(!user) {
            return res.status(401).json({
                status: "Unauthorized",
                message: "Username or password is incorrect."
            })
        }

        email = emailMask(user.email);
    }

    if(!/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/i.test(password)) {
        return res.status(400).send({
            status: "Bad Request",
            message: "Type a valid password. Minimum eight characters, at least one letter and one number."
        })
    }

    if(await bcrypt.compare(password, user.password)) {
        if(user.emailConfirmed == false) {
            return res.json({
                status: "OK",
                message: "Please, confirm your email before login."
            });
        };

        user.password = undefined;

        const token = generateToken({ id: user.id, type: 'login' }, 86400);

        return res.json({
            status: "OK",
            message: "Authenticated successfully.",
            token: token,
            user: user
        });
    } else {
        return res.status(401).json({
            status: "Unauthorized",
            message: "Username or password is incorrect."
        })
    }
});

router.post('/register', async function (req, res) {
    try {
        const { username, email, password } = req.body;

        const contains = await containKeys(req.body, ['username', 'email', 'password']);

        if(contains.length > 0) {
            return res.status(400).send({
                status: "Bad Request",
                message: `Parameters [${contains.join(', ')}] are missing.`
            })
        }

        if(await User.findOne({ username })) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Username already exists."
            })
        }

        if(await User.findOne({ email })) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Email already exists."
            })
        }

        if(!/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(email)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Type a valid email address. Ex.: example@desastrad0.com"
            })
        }

        if(!/^(?=[a-zA-Z0-9._]{3,20}$)(?!.*[_.]{2})[^_.].*[^_.]$/i.test(username)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Type a valid username. Are allowed letters, numbers, dots and underscores."
            })
        }

        if(!/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/i.test(password)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Type a valid password. Minimum eight characters, at least one letter and one number."
            })
        }

        const user = await User.create(req.body);

        user.password = undefined;

        const token = generateToken({ id: user.id, type: 'email' }, 1800);
        const sended = await sendEmail({
            from: "email-confirmation@desastrad0.com",
            to: email,
            subject: "Email Confirmation",
            text: `http://localhost/email/confirmate?token=${token}`
        });

        if(sended.response.includes('Ok')) {
            return res.json({
                status: "OK",
                message: "Registered successfully, confirm your e-mail."
            });
        } else {
            return res.status(500).json({
                status: "Internal Server Error",
                message: "Confirmation email cannot be sent."
            });
        }
    } catch (err) {
        console.log(err);
        return res.status(500).json({
            status: "Internal Server Error",
            message: "An internal error occurred."
        });
    }
});

module.exports = app => app.use('/auth', router);