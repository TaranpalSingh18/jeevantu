const mongoose = require('mongoose');

const StockSchema = new mongoose.Schema({
    pname: { type: String, required: true },
    mrp: { type: String, required: true, unique: true },
    value: { type: Number, required: true },
});

module.exports = mongoose.model("Stock", StockSchema);
