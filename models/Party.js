const mongoose = require('mongoose');

// Cria a collection
const Party = mongoose.model('Parties', {
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
    },
});

module.exports = Party;