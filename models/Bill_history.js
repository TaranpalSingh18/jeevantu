const mongoose = require('mongoose');
const productSchema=require('./Stock')

const billhistorySchema = new mongoose.Schema({
    Customer_name: { type: String, required: true },
    Mobile_No: { type: String, required: true, unique: true },
    items: { type: [productSchema], required: true }
});

module.exports = mongoose.model("billhistory", billhistorySchema);
