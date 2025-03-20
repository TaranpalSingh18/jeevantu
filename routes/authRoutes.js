const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Cashier = require('../models/Cashier');
const User = require('../models/User');
require('dotenv').config({path: '../.env'});
const router = express.Router();



// Cashier Signup
router.post('/cashier/signup', async (req, res) => {
    try {
        const { name, email, password, confirmpassword } = req.body;

        if (password !== confirmpassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newCashier = new Cashier({ name, email, password: hashedPassword });
        await newCashier.save();

        res.status(201).json({ message: "Cashier registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error", error });
    }
});

// Cashier Login
router.post('/cashier/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const cashier = await Cashier.findOne({ email });

        if (!cashier || !(await bcrypt.compare(password, cashier.password))) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ id: cashier._id }, 'your_secret_key', { expiresIn: '1h' });

        res.json({ message: "Login successful", token });
    } catch (error) {
        res.status(500).json({ message: "Server error", error });
    }
});

// User Signup
router.post('/user/signup', async (req, res) => {
    try {
        const { name, email, address, password, confirmpassword } = req.body;

        if (password !== confirmpassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ name, email, address, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error", error });
    }
});

// User Login
router.post('/user/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user._id }, 'your_secret_key', { expiresIn: '1h' });

        res.json({ message: "Login successful", token });
    } catch (error) {
        res.status(500).json({ message: "Server error", error });
    }
});

router.post('/admin/login', (req, res) => {
    const { email, password } = req.body;

    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {


        res.json({
            message: "Admin login successful",
         
        });
    } else {
        res.status(403).json({ message: "Unauthorized: Invalid credentials" });
    }
});


module.exports = router;
