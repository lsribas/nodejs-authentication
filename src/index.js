const express = require('express');
const app = express();

app.use(express.json());

require('./routes/auth')(app);
require('./routes/customer')(app);
require('./routes/email')(app);
require('./routes/password')(app);

app.all('*', function (req, res) {
    res.sendStatus(405)
});

app.listen(80);