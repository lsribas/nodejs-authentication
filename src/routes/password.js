const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../database/user');
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
    try {
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
            user = await User.findOne({ email: identification }).select('+recoveryCode').select('+recoveryCodeExpiration').select('+recoveryCodeCooldown');

            if(!user) {
                return res.status(400).send({
                    status: "Bad Request",
                    message: "Username/email isn't registered."
                })
            }

            email = user.email;
        } else {
            user = await User.findOne({ username: identification }).select('+recoveryCode').select('+recoveryCodeExpiration').select('+recoveryCodeCooldown');

            if(!user) {
                return res.status(400).send({
                    status: "Bad Request",
                    message: "Username/email isn't registered."
                })
            }

            email = emailMask(user.email);
        }

        if(user.recoveryCodeCooldown > Date.now()) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Wait 5 minutes before asking for a new code."
            })
        }

        const code = Math.floor(Math.random() * 999999).toString().padStart(6, "0");
        const expireDate = new Date().setMinutes(new Date().getMinutes() + 30);
        const cooldown = new Date().setMinutes(new Date().getMinutes() + 5);
        const sended = await sendEmail({
            from: "password-recovery@desastrad0.com",
            to: user.email,
            subject: "Reset your password",
            text: `Your password reset code is: ${code}. (Valid for 30 minutes only)`
        });

        if(sended.response.includes('Ok')) {
            user.recoveryCode = code;
            user.recoveryCodeExpiration = expireDate;
            user.recoveryCodeCooldown = cooldown;
            await user.save();

            return res.json({
                status: "OK",
                message: `Code to recover your password successfully sent. Email: '${email}'.`
            });
        } else {
            return res.status(500).json({
                status: "Internal Server Error",
                message: `Code to recover your password cannot be sent. Email: '${email}'.`
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
            user = await User.findOne({ email: identification }).select('+password').select('+recoveryCode').select('+recoveryCodeExpiration');
    
            if(!user) {
                return res.status(400).send({
                    status: "Bad Request",
                    message: "Username/email isn't registered."
                })
            }
        } else {
            user = await User.findOne({ username: identification }).select('+password').select('+recoveryCode').select('+recoveryCodeExpiration');
    
            if(!user) {
                return res.status(400).send({
                    status: "Bad Request",
                    message: "Username/email isn't registered."
                })
            }
        }

        if(user.recoveryCode != code || user.recoveryCodeExpiration < Date.now()) {
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
                message: "Your new password must not be the same as your current password.."
            })
        }

        user.recoveryCode = undefined;
        user.recoveryCodeExpiration = undefined;
        user.recoveryCodeCooldown = undefined;
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