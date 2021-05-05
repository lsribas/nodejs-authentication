//Dependencias
const express = require('express');
const app = express();
const users = require('./users.json');
app.use(express.json());

//Rota de login
app.post('/login', function (req, res) {
    if(users.find(u => u.user == req.body.user && u.pass == req.body.pass )) {
        res.status(200).send({
            status: "Authenticated",
            message: "Autenticado com sucesso."
        });
    } else {
        res.status(401).send({
            status: "Unauthorized",
            message: "Usuário ou senha incorretos."
        })
    }
});

//Em caso de utilizar uma rota não existente ou método não permitido.
app.all('*', function (req, res) {
    res.sendStatus(405)
})

//Atender a essa porta.
app.listen(80, () => {
    console.log(`Online na porta: 80.`)
});