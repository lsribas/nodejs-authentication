const express = require('express');
const jwt = require('jsonwebtoken');
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

function generateToken(params, time) {
    return jwt.sign(params, secret, {
        expiresIn: time,
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

router.post('/resend', async function (req, res) {
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
        user = await User.findOne({ email: identification });

        if(!user) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Username/email isn't registered."
            })
        }

        email = user.email;
    } else {
        user = await User.findOne({ username: identification });

        if(!user) {
            return res.status(400).send({
                status: "Bad Request",
                message: "Username/email isn't registered."
            })
        }

        email = emailMask(user.email);
    }

    if(user.emailConfirmed == true) {
        return res.status(200).json({
            status: "OK",
            message: "Email already confirmed."
        })
    }

    const token = generateToken({ id: user.id, type: 'email' }, 1800);
    const sended = await sendEmail({
        from: "email-confirmation@desastrad0.com",
        to: user.email,
        subject: "Email Confirmation",
        text: `http://localhost/email/confirmate?token=${token}`
    });

    if(sended.response.includes('Ok')) {
        return res.json({
            status: "OK",
            message: `Confirmation email successfully resent. E-mail: '${email}'.`
        });
    } else {
        return res.status(500).json({
            status: "Internal Server Error",
            message: `Confirmation email cannot be sent. E-mail: '${email}'.`
        });
    }
});

router.get('/confirmate', async function (req, res) {
    try {
        const token = req.query.token;

        if(!token) {
            return res.status(401).json({
                status: "Unauthorized",
                message: "No provided token."
            })
        }

        jwt.verify(token, secret, async (err, jwt) => {
            if (err) {
                return res.status(401).json({
                    status: "Unauthorized",
                    message: "Invalid token."
                })
              }
        
            if (jwt.type != 'email') {
                return res.status(401).json({
                    status: "Unauthorized",
                    message: "Invalid token."
                })
              }
        
            const _id = jwt.id;
            const user = await User.findOne({ _id });

            if(!user) {
                return res.status(401).json({
                    status: "Unauthorized",
                    message: "Expired token."
                })
            }

            if(user.emailConfirmed == true) {
                return res.status(200).json({
                    status: "OK",
                    message: "Email already confirmed."
                })
            }

            user.emailConfirmed = true;
            await user.save();

            return res.json({
                status: "OK",
                message: "Email successfully confirmed."
            });
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({
            status: "Internal Server Error",
            message: "An internal error occurred."
        });
    }
});

module.exports = app => app.use('/email', router);