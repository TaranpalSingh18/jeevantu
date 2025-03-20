const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const router = express.Router();
require('dotenv').config({path: '../.env'});

const Admin = require("../models/Admin");
const Bill = require("../models/Bill");
const Product = require("../models/Product");   
const PurchaseOrder = require("../models/PurchaseOrder");
const CashierRequest = require("../models/CashierRequest");

const authenticateAdmin = async (req, res, next) => {
  const token = req.header("Authorization");
  if (!token)
    return res.status(401).json({ message: "Access denied. No token provided." });
  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ message: "Unauthorized: Admin access only." });
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid token." });
  }
};

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password are required" });
  try {
    const admin = await Admin.findOne({ email });
    if (!admin)
      return res.status(403).json({ message: "Unauthorized: Invalid credentials" });
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch)
      return res.status(403).json({ message: "Unauthorized: Invalid credentials" });
    const token = jwt.sign({ role: "admin", email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ message: "Admin login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.post("/generate-bill", authenticateAdmin, async (req, res) => {
  const { items, totalAmount } = req.body;
  if (!items || !totalAmount)
    return res.status(400).json({ message: "Invalid bill data" });
  try {
    const newBill = new Bill({ items, totalAmount, createdBy: req.admin.email });
    await newBill.save();
    res.status(201).json({ message: "Bill generated successfully", bill: newBill });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.put("/stock/update", authenticateAdmin, async (req, res) => {
  const { productId, quantity } = req.body;
  if (!productId || quantity === undefined)
    return res.status(400).json({ message: "Product ID and quantity required" });
  try {
    const product = await Product.findById(productId);
    if (!product)
      return res.status(404).json({ message: "Product not found" });
    product.stock = quantity;
    await product.save();
    res.status(200).json({
      message: "Stock updated successfully",
      productId,
      updatedStock: product.stock,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.get("/stock", authenticateAdmin, async (req, res) => {
  try {
    const inventory = await Product.find({});
    res.status(200).json({ message: "Stock and inventory details fetched", inventory });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.get("/low-stock", authenticateAdmin, async (req, res) => {
  const LOW_STOCK_THRESHOLD = 5;
  try {
    const warnings = await Product.find({ stock: { $lt: LOW_STOCK_THRESHOLD } });
    res.status(200).json({ message: "Low stock warnings", warnings });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.post("/purchase-orders", authenticateAdmin, async (req, res) => {
  const { supplier, items } = req.body;
  if (!supplier || !items)
    return res.status(400).json({ message: "Invalid purchase order data" });
  try {
    const newPO = new PurchaseOrder({ supplier, items, createdBy: req.admin.email });
    await newPO.save();
    res.status(201).json({ message: "Purchase order recorded successfully", purchaseOrder: newPO });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.get("/history", authenticateAdmin, async (req, res) => {
  try {
    const bills = await Bill.find({});
    const purchaseOrders = await PurchaseOrder.find({});
    res.status(200).json({ message: "Billing and purchase history fetched", bills, purchaseOrders });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.put("/cashier-requests", authenticateAdmin, async (req, res) => {
  const { cashierId, status } = req.body;
  if (!cashierId || !status)
    return res.status(400).json({ message: "Cashier ID and status required" });
  try {
    const request = await CashierRequest.findById(cashierId);
    if (!request)
      return res.status(404).json({ message: "Cashier request not found" });
    request.status = status;
    await request.save();
    res.status(200).json({
      message: "Cashier request updated successfully",
      cashierId,
      newStatus: request.status,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

module.exports = router;
