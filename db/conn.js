const mongoose = require("mongoose");
require('dotenv').config();

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

async function main() {
    try {
        //mongoose.set("strictQuery", true);
        /*
        await mongoose.connect(
            "mongodb+srv://andreavancini:eCRLH5McYPmrVniT@cluster0.v6l5gpj.mongodb.net/?retryWrites=true&w=majority"
        );
        */
        
        await mongoose.connect(
            `mongodb+srv://${dbUser}:${dbPass}@cluster0.wpemlmw.mongodb.net/test`
        )
        
        console.log(" ======== Conectado ao BD ======== ")
    } catch (error) {
        console.log(`Erro: ${error}`);
    }
}

module.exports = main;