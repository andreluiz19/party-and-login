const mongoose = require('mongoose');

// Cria a collection
const User = mongoose.model('User', {
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

module.exports = User;