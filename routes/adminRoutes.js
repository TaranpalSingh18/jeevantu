const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const router = express.Router();


dotenv.config({ path: "../.env" });


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
      // Verify the token and decode it
      const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
  
      // Check if the role is "admin"
      if (decoded.role !== "admin")
        
        return res.status(403).json({ message: "Unauthorized: Admin access only." });
  
      // Attach the decoded admin data to the request object
      req.admin = decoded;
      next();
    } catch (err) {
      res.status(400).json({ message: "Invalid token." });
    }
  };

router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    try {
        console.log("Email received:", email);
        
        const admin = await Admin.findOne({ email });
        if (!admin) {
            console.log("Admin not found");
            return res.status(403).json({ message: "Unauthorized: Invalid credentials" });
        }

        console.log("Admin found:", admin);
        console.log("Received password:", password);


        const isMatch = await bcrypt.compare(password, admin.password.trim());

        if (!isMatch) {
            console.log("Password does not match");
            return res.status(403).json({ message: "Unauthorized: Invalid credentials" });
        }

        console.log("Password matches, generating token");

        const token = jwt.sign(
            { role: admin.role, email: admin.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({ message: "Admin login successful", token });
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});


router.post("/generate-bill", authenticateAdmin, async (req, res) => {
  const { items, totalAmount } = req.body;

  // Validate input
  if (!items || !totalAmount)
    return res.status(400).json({ message: "Invalid bill data" });

  try {
    // Create a new bill
    const newBill = new Bill({ items, totalAmount, createdBy: req.admin.email });
    await newBill.save();

    // Send success response
    res.status(201).json({ message: "Bill generated successfully", bill: newBill });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});


router.put("/stock/update", authenticateAdmin, async (req, res) => {
  const { productId, quantity } = req.body;

  // Validate input
  if (!productId || quantity === undefined)
    return res.status(400).json({ message: "Product ID and quantity required" });

  try {

    const product = await Product.findById(productId);
    if (!product)
      return res.status(404).json({ message: "Product not found" });

    // Update the stock quantity
    product.stock = quantity;
    await product.save();

    // Send success response
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
    // Fetch all products
    const inventory = await Product.find({});
    res.status(200).json({ message: "Stock and inventory details fetched", inventory });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Get low stock warnings route (protected)
router.get("/low-stock", authenticateAdmin, async (req, res) => {
  const LOW_STOCK_THRESHOLD = 5; // Define the threshold for low stock

  try {
    // Find products with stock less than the threshold
    const warnings = await Product.find({ stock: { $lt: LOW_STOCK_THRESHOLD } });
    res.status(200).json({ message: "Low stock warnings", warnings });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Create purchase order route (protected)
router.post("/purchase-orders", authenticateAdmin, async (req, res) => {
  const { supplier, items } = req.body;

  // Validate input
  if (!supplier || !items)
    return res.status(400).json({ message: "Invalid purchase order data" });

  try {
    // Create a new purchase order
    const newPO = new PurchaseOrder({ supplier, items, createdBy: req.admin.email });
    await newPO.save();

    // Send success response
    res.status(201).json({ message: "Purchase order recorded successfully", purchaseOrder: newPO });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Get billing and purchase history route (protected)
router.get("/history", authenticateAdmin, async (req, res) => {
  try {
    // Fetch all bills and purchase orders
    const bills = await Bill.find({});
    const purchaseOrders = await PurchaseOrder.find({});
    res.status(200).json({ message: "Billing and purchase history fetched", bills, purchaseOrders });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Update cashier request status route (protected)
router.put("/cashier-requests", authenticateAdmin, async (req, res) => {
  const { cashierId, status } = req.body;

  // Validate input
  if (!cashierId || !status)
    return res.status(400).json({ message: "Cashier ID and status required" });

  try {
    // Find the cashier request by ID
    const request = await CashierRequest.findById(cashierId);
    if (!request)
      return res.status(404).json({ message: "Cashier request not found" });

    // Update the status
    request.status = status;
    await request.save();

    // Send success response
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