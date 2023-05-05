const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());

// DB Connection
const conn = require("./db/conn");

// Routes
const routes = require("./routes/router");
app.use("/api", routes);


// LOGIN 
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

// Registro de Usuário
app.post('/auth/register', async (req, res) => {

    const { email, password, confirmPassword } = req.body;
    
    // Validações
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ msg: "As senhas não conferem!" });
    }

    // Verificando se o usuário existe
    const userExist = await User.findOne({ email: email });

    if (userExist) {
        return res.status(422).json({ msg: "Favor, utilize outro email!" });
    }

    // Criando senha
    // Gerando caracteres aleatórios
    const salt = await bcrypt.genSalt(12);
    const hashPass = await bcrypt.hash(password, salt);

    // Criando usuário
    const user = new User({
        email,
        password: hashPass,
    });

    try {

        await user.save();

        // Status 201 -> Algo foi registrado no banco de dados
        res.status(201).json({ msg: "Usuário criado com sucesso!" });

    } catch (error) {

        console.log(`Erro: ${error}`);
        // Status 500 -> Erro interno no servidor
        res.status(500).json({ msg: "Erro no servidor, tente novamente mais tarde!" });

    }
});

// Login User
app.post("/auth/login", async (req, res) => {

    const { email, password } = req.body;

    // Validações
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
    }

    // Verificando se o usuário existe
    const user = await User.findOne({ email: email });

    if (!user) {
        // Status 404 -> Não encontrado
        return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    // Verificando senha
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida!" });
    }

    try {

        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user.id,
            },
            secret,
            {
                //expiresIn: 300 // 5 Minutos
            }
        );
        // Satatus 200 -> Sucesso
        res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });

    } catch (error) {

        console.log(`Erro: ${error}`);
        // Status 500 -> Erro interno no servidor
        res.status(500).json({ msg: "Erro no servidor, tente novamente mais tarde!" });

    }
});

app.listen(3000, function () {
    console.log(" ======== SERVIDOR ONLINE ======== ");
    conn();
});

