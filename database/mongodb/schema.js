const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const orderSchema = new mongoose.Schema({
    email: String,
    name: String,
    status: String
});

module.exports = {
    userSchema,
    orderSchema
};


