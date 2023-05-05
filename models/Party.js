const mongoose = require('mongoose');

const { Schema } = mongoose;

const partySchema = new Schema({
    //name: String
    title: {
        type: String,
        required: true
    },
    author: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    budget: {
        type: String,
        required: true
    }
});

const Party = mongoose.model('Parties', partySchema); 

module.exports = {
    Party,
    partySchema
};