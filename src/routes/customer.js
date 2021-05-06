const express = require('express');
const User = require('../database/user');
const authenticateReq = require('../authenticate/token');

const router = express.Router();

router.use(authenticateReq);

router.get('/info', async function (req, res) {
    try {
        const _id = req.userId;

        const user = await User.findOne({ _id });

        if(!user) {
            return res.status(401).json({
                status: "Unauthorized",
                message: "Expired token."
            })
        }

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

module.exports = app => app.use('/customer', router);