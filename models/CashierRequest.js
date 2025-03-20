const mongoose = require("mongoose");

const cashierRequestSchema = new mongoose.Schema({
  cashierId: String,
  status: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("CashierRequest", cashierRequestSchema);
