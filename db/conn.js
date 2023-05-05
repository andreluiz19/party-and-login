const mongoose = require("mongoose");
require('dotenv').config();

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

async function main() {
    try {
        await mongoose.connect(
            `mongodb+srv://${dbUser}:${dbPass}@cluster0.wpemlmw.mongodb.net/test`
        )
        
        console.log(" ======== CONECTADO AO BD ======== ")
    } catch (error) {
        console.log(`Erro: ${error}`);
    }
}

module.exports = main;