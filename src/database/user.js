const mongoose = require('./index.js');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        select: false
    },
    emailConfirmed: {
        type: Boolean,
        default: false
    },
    recoveryCode: {
        type: String,
        select: false
    },
    recoveryExpiration: {
        type: Date,
        select: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    versionKey: false
});

UserSchema.pre('save', async function(next) {
    if(this.password) {
        const hash = await bcrypt.hash(this.password, 10);
        this.password = hash;
    }
    next();
})

const User = mongoose.model('User', UserSchema);

module.exports = User;