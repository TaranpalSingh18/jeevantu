const mongoose = require("mongoose");

const purchaseOrderSchema = new mongoose.Schema({
  supplier: String,
  items: [
    {
      name: String,
      quantity: Number,
      price: Number
    }
  ],
  createdBy: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("PurchaseOrder", purchaseOrderSchema);
