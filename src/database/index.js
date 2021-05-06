const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/database', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

mongoose.Promise = global.Promise;

module.exports = mongoose;