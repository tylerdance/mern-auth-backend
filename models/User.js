const mongoose = require('mongoose')
const Schema = mongoose.Schema

// User schema
const userSchema = new Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
        minLength: 8,
    },
    date: {
        type: Date,
        default: Date.now()
    }
});

const User = mongoose.Model('User', userSchema);

module.exports = User;