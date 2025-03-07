const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true },
    username: { type: String }, 
    walletAddress: { type: String, required: true },
    encryptedPrivateKey: { type: String, required: true },
    securityCode: { type: String, required: false },
});

const User = mongoose.model('User', userSchema);
module.exports = User;
