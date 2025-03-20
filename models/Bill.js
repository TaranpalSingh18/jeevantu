const mongoose = require("mongoose");

const billSchema = new mongoose.Schema({
  items: [
    {
      name: String,
      quantity: Number,
      price: Number
    }
  ],
  totalAmount: Number,
  createdBy: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Bill", billSchema);
