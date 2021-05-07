const express = require('express');
const User = require('../database/user');
const jwt = require('jsonwebtoken');
const authenticateReq = require('../authenticate/token');
const { secret } = require('../config/auth.json');
const bcrypt = require('bcryptjs');
const mailer = require('../modules/mailer.js');

const router = express.Router();

router.use(authenticateReq);

function emailMask(email) {
	var maskedEmail = email.replace(/([^@\.])/g, "*").split('');
	var previous	= "";
	for(i=0;i<maskedEmail.length;i++){
		if (i<=1 || previous == "." || previous == "@"){
			maskedEmail[i] = email[i];
		}
		previous = email[i];
	}
	return maskedEmail.join('');
};

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

router.get('/info', async function (req, res) {
    try {
        const { user } = req;

        return res.json({
            status: "OK",
            user: user
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({
            status: "Internal Server Error",
            message: "An internal error occurred."
        });
    }
});

router.post('/change-password', async function (req, res) {
    try {

        const { currentPass, newPass, confirmPass } = req.body,
            user = await User.findOne({ _id: req.user._id }).select('+password'),
            contains = await containKeys(req.body, ['currentPass', 'newPass', 'confirmPass']);

        if(contains.length > 0) {
            return res.status(400).send({
                status: "Bad Request",
                message: `Parameters [${contains.join(', ')}] are missing.`
            })
        }

        if(!await bcrypt.compare(currentPass, user.password)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Current password is wrong."
            })
        }

        if(!/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/i.test(newPass)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Type a valid password. Minimum eight characters, at least one letter and one number."
            })
        }

        if(newPass != confirmPass) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Passwords do not match."
            })
        }

        if(await bcrypt.compare(newPass, user.password)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Passwords must be not the same."
            })
        }

        const sended = await sendEmail({
            from: "account-security@desastrad0.com",
            to: user.email,
            subject: "Account Security",
            text: `Your password was changed.`
        });

        if(sended.response.includes('Ok')) {
            user.password = newPass;
            await user.save();

            const token = generateToken({ id: user.id, password: user.password, type: 'login' }, 86400);

            return res.json({
                status: "OK",
                message: "Password successfully changed.",
                token
            });
        } else {
            return res.status(500).json({
                status: "Internal Server Error",
                message: `Wasn't possible to change your password.`
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

router.get('/change-email', async function (req, res) {
    try {
        const user = await User.findOne({ _id: req.user._id }).select('+emailChangeCode').select('+emailChangeCodeExpiration').select('+emailChangeCodeCooldown');

        if(user.emailChangeCodeCooldown > Date.now()) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Wait 5 minutes before asking for a new code."
            })
        }

        const code = Math.floor(Math.random() * 999999).toString().padStart(6, "0");
        const expireDate = new Date().setMinutes(new Date().getMinutes() + 30);
        const cooldown = new Date().setMinutes(new Date().getMinutes() + 5);
        
        const sended = await sendEmail({
            from: "email-change@desastrad0.com",
            to: user.email,
            subject: "Email Change",
            text: `The code to change your email is: ${code}. (Valid for 30 minutes only)`
        });

        if(sended.response.includes('Ok')) {
            user.emailChangeCode = code;
            user.emailChangeCodeExpiration = expireDate;
            user.emailChangeCodeCooldown = cooldown;
            await user.save();
            return res.json({
                status: "OK",
                message: `Code to change your email successfully sent. Email: '${emailMask(user.email)}'.`
            });
        } else {
            return res.status(500).json({
                status: "Internal Server Error",
                message: `Code to change your email cannot be sent. Email: '${emailMask(user.email)}'.`
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

router.post('/change-email', async function (req, res) {
    try {
        const { code, newEmail, confirmEmail } = req.body,
            user = await User.findOne({ _id: req.user._id }).select('+emailChangeCode').select('+emailChangeCodeExpiration').select('+emailChangeCodeCooldown');

        if(!code) {
            return res.status(401).json({
                status: "Unauthorized",
                message: "No provided code."
            })
        }

        const contains = await containKeys(req.body, ['code', 'newEmail', 'confirmEmail']);

        if(contains.length > 0) {
            return res.status(400).send({
                status: "Bad Request",
                message: `Parameters [${contains.join(', ')}] are missing.`
            })
        }

        if(user.emailChangeCode != code || user.emailChangeCodeExpiration < Date.now()) {
            return res.status(401).send({
                status: "Unauthorized",
                message: "Invalid or expired code."
            })
        }

        if(!/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(newEmail)) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Type a valid email address. Ex.: example@desastrad0.com"
            })
        }

        if(newEmail != confirmEmail) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Emails do not match."
            })
        }

        if(newEmail == user.email) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Your new email must not be the same as your current email."
            })
        }

        const token = generateToken({ id: user.id, email: user.email, newEmail, type: 'change-email' }, 86400);
        const sended = await sendEmail({
            from: "email-change-confirmation@desastrad0.com",
            to: newEmail,
            subject: "Email Change Confirmation",
            text: `To confirm the change click on the following link: http://localhost/email/confirm-change?token=${token}`
        });

        if(sended.response.includes('Ok')) {
            user.emailChangeCode = undefined;
            user.emailChangeCodeExpiration = undefined;
            user.emailChangeCodeCooldown = undefined;
            await user.save();

            return res.json({
                status: "OK",
                message: `To confirm your change, confirm in the new email. New email: ${newEmail}`
            });
        } else {
            return res.status(500).json({
                status: "Internal Server Error",
                message: `Was not possible to change your email. New email: ${newEmail}`
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

module.exports = app => app.use('/customer', router);