const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../database/user');
const { secret } = require('../config/auth.json');
const mailer = require('../modules/mailer.js');

const router = express.Router();

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

router.post('/forgot', async function (req, res) {
    const { identification } = req.body;

    const contains = await containKeys(req.body, ['identification']);
    let user,
        email;

    if(contains.length > 0) {
        return res.status(400).send({
            status: "Bad Request",
            message: `Parameters [${contains.join(', ')}] are missing.`
        })
    }

    if(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(identification)) {
        user = await User.findOne({ email: identification }).select('+recoveryCode').select('+recoveryExpiration');

        if(!user) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Username/email isn't registered."
            })
        }

        email = user.email;
    } else {
        user = await User.findOne({ username: identification }).select('+recoveryCode').select('+recoveryExpiration');

        if(!user) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Username/email isn't registered."
            })
        }

        email = emailMask(user.email);
    }

    if(user.recoveryExpiration > Date.now()) {
        return res.status(400).send({
            status: "Bad Request",
            message: "Wait 5 minutes before asking for another code."
        })
    }

    const code = Math.floor(Math.random() * 9999).toString().padStart(4, "0");
    const expireDate = new Date().setMinutes(new Date().getMinutes() + 5);
    user.recoveryCode = code;
    user.recoveryExpiration = expireDate;
    await user.save();
    
    const sended = await sendEmail({
        from: "password-recovery@desastrad0.com",
        to: user.email,
        subject: "Reset your password",
        text: `Your password reset code is: ${code}`
    });

    if(sended.response.includes('Ok')) {
        return res.json({
            status: "OK",
            message: `Password recovery email successfully sent. E-mail: '${email}'.`
        });
    } else {
        return res.status(500).json({
            status: "Internal Server Error",
            message: `Password recovery email cannot be sent. E-mail: '${email}'.`
        });
    }
});

router.post('/reset', async function (req, res) {
    try {
        const { identification, code, newPass, confirmPass } = req.body;
        let user;

        if(!code) {
            return res.status(401).json({
                status: "Unauthorized",
                message: "No provided code."
            })
        }

        const contains = await containKeys(req.body, ['identification', 'code', 'newPass', 'confirmPass']);

        if(contains.length > 0) {
            return res.status(400).send({
                status: "Bad Request",
                message: `Parameters [${contains.join(', ')}] are missing.`
            })
        }

        if(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(identification)) {
            user = await User.findOne({ email: identification }).select('+password').select('+recoveryCode').select('+recoveryExpiration');
    
            if(!user) {
                return res.status(400).send({
                    status: "Bad Request",
                    message: "Username/email isn't registered."
                })
            }
        } else {
            user = await User.findOne({ username: identification }).select('+password').select('+recoveryCode').select('+recoveryExpiration');
    
            if(!user) {
                return res.status(400).send({
                    status: "Bad Request",
                    message: "Username/email isn't registered."
                })
            }
        }

        if(user.recoveryCode != code || user.recoveryExpiration < Date.now()) {
            return res.status(401).send({
                status: "Unauthorized",
                message: "Invalid or expired code."
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

        user.recoveryCode = undefined;
        user.recoveryExpiration = undefined;
        user.password = newPass;
        await user.save();

        return res.json({
            status: "OK",
            message: "Password successfully reset."
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({
            status: "Internal Server Error",
            message: "An internal error occurred."
        });
    }
});

module.exports = app => app.use('/password', router);