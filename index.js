const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/authRoutes');
const adminRoutes =require('./routes/adminRoutes');
require('dotenv').config({path: ".env"});

const PORT = process.env.PORT;

const app = express();
app.use(express.json());


mongoose.connect(process.env.MONGO_URI, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);
// app.use('/cashier', cashierRoutes);
// app.use('/user', userRoutes);


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
