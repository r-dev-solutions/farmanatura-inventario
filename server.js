require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { authenticate, validate } = require('./middleware/auth');
const { body } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

// Security middleware
app.use(helmet()); // Set various HTTP headers for security
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS || '*', // Restrict to specific origins
    methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parser
app.use(express.json({ limit: '10kb' })); // Limit JSON body size

// MongoDB connection with improved error handling
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit process on connection failure
});

// Define Inventory Schema directly in server.js
const inventorySchema = new mongoose.Schema({
    codigoProducto: {
        type: String,
        required: [true, 'El código del producto es requerido'],
        unique: true,
        trim: true,
        maxlength: [20, 'El código no puede exceder 20 caracteres'],
        match: [/^[A-Z0-9-]+$/, 'El código debe contener solo letras mayúsculas, números y guiones']
    },
    nombre: {
        type: String,
        required: [true, 'El nombre del producto es requerido'],
        trim: true,
        maxlength: [100, 'El nombre no puede exceder 100 caracteres']
    },
    descripcion: {
        type: String,
        required: [true, 'La descripción es requerida'],
        maxlength: [500, 'La descripción no puede exceder 500 caracteres']
    },
    categoria: {
        type: String,
        required: true,
        enum: ['Vitamina', 'Mineral', 'Herbal', 'Proteína', 'Probiótico', 'Otro']
    },
     ingredientes: [{
        nombre: String
    }],
    precio: {
        type: String,
        match: [/^C\$[0-9]+(\.[0-9]{2})?$/, 'El precio debe estar en formato C$ (ej: C$100 o C$99.99)']
    },
    instruccionesUso: {
        type: String,
        maxlength: [1000, 'Las instrucciones no pueden exceder 1000 caracteres']
    },
    descuento: {
        type: Number,
        min: [0, 'El descuento no puede ser negativo'],
        max: [100, 'El descuento no puede exceder 100%']
    },
    cantidad: {
        type: Number,
        required: true,
        min: [0, 'La cantidad no puede ser negativa']
    },
    Precio$: {
        type: Number,
        required: true,
        min: [0, 'El precio no puede ser negativo']
    },
    fechaExpiracion: {
        type: Date,
        required: true
    },
    urlImagen1: {
        type: String,
        match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Por favor ingrese una URL válida']
    },
    urlImagen2: {
        type: String,
        match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Por favor ingrese una URL válida']
    },
    urlImagen3: {
        type: String,
        match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Por favor ingrese una URL válida']
    },
    urlImagen4: {
        type: String,
        match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Por favor ingrese una URL válida']
    },
    urlImagen5: {
        type: String,
        match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Por favor ingrese una URL válida']
    },
    fechaCreacion: {
        type: Date,
        default: Date.now
    },
    fechaActualizacion: {
        type: Date,
        default: Date.now
    }
});

// Update the updatedAt field before saving
inventorySchema.pre('save', function(next) {
    this.fechaActualizacion = Date.now();
    next();
});

const Inventory = mongoose.model('Inventory', inventorySchema);

// GET all inventory items
app.get('/api/inventory', async (req, res) => {
    try {
        const items = await Inventory.find();
        res.json(items);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// GET single inventory item
app.get('/api/inventory/:id', async (req, res) => {
    try {
        const item = await Inventory.findById(req.params.id);
        if (!item) return res.status(404).json({ message: 'Item no encontrado' });
        res.json(item);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// POST new inventory item
app.post('/api/inventory', validate([
    body('nombre').isString().notEmpty(),
    body('descripcion').isString().notEmpty(),
    body('categoria').isIn(['Vitamina', 'Mineral', 'Herbal', 'Proteína', 'Probiótico', 'Otro']),
    body('cantidad').isInt({ min: 0 }),
    body('precio').isFloat({ min: 0 })
]), async (req, res) => {
    try {
        const newItem = new Inventory(req.body);
        const savedItem = await newItem.save();
        res.status(201).json(savedItem);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// PUT update inventory item
app.put('/api/inventory/:id', validate([
    body('nombre').optional().isString().notEmpty(),
    body('descripcion').optional().isString().notEmpty(),
    body('categoria').optional().isIn(['Vitamina', 'Mineral', 'Herbal', 'Proteína', 'Probiótico', 'Otro']),
    body('cantidad').optional().isInt({ min: 0 }),
    body('precio').optional().isFloat({ min: 0 })
]), async (req, res) => {
    try {
        const item = await Inventory.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );
        if (!item) return res.status(404).json({ message: 'Item no encontrado' });
        res.json(item);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// DELETE inventory item
app.delete('/api/inventory/:id', async (req, res) => {
    try {
        const item = await Inventory.findByIdAndDelete(req.params.id);
        if (!item) return res.status(404).json({ message: 'Item no encontrado' });
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Remove user schema and authentication routes
// const userSchema = new mongoose.Schema({
//     username: { type: String, unique: true, required: true },
//     password: { type: String, required: true }
// });
// const User = mongoose.model('User', userSchema);

// Remove register and login routes
// app.post('/api/register', validate([
//     body('username').isLength({ min: 3 }),
//     body('password').isLength({ min: 6 })
// ]), async (req, res) => {
//     try {
//         const hashedPassword = await bcrypt.hash(req.body.password, 10);
//         const user = new User({
//             username: req.body.username,
//             password: hashedPassword
//         });
//         await user.save();
//         res.status(201).json({ message: 'User registered successfully' });
//     } catch (err) {
//         res.status(400).json({ message: err.message });
//     }
// });

// app.post('/api/login', validate([
//     body('username').exists(),
//     body('password').exists()
// ]), async (req, res) => {
//     try {
//         const user = await User.findOne({ username: req.body.username });
//         if (!user || !await bcrypt.compare(req.body.password, user.password)) {
//             return res.status(400).json({ message: 'Invalid credentials' });
//         }
        
//         const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
//             expiresIn: process.env.JWT_EXPIRES_IN
//         });
//         res.json({ token });
//     } catch (err) {
//         res.status(500).json({ message: err.message });
//     }
// });

// Add a simple token verification endpoint
app.post('/api/verify-token', (req, res) => {
    const token = req.body.token;
    if (!token) {
        return res.status(400).json({ message: 'Token is required' });
    }
    
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        res.json({ valid: true });
    } catch (err) {
        res.status(401).json({ valid: false, message: 'Invalid token' });
    }
});

// Protect inventory routes
app.use('/api/inventory', authenticate);

// Update inventory routes with validation
app.post('/api/inventory', validate([
    body('name').isString().notEmpty(),
    body('quantity').isInt({ min: 0 }),
    body('price').isFloat({ min: 0 })
]), async (req, res) => {
    const item = new Inventory({
        name: req.body.name,
        quantity: req.body.quantity,
        price: req.body.price
    });

    try {
        const newItem = await item.save();
        res.status(201).json(newItem);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// PUT update inventory item
app.put('/api/inventory/:id', async (req, res) => {
    try {
        const item = await Inventory.findById(req.params.id);
        if (!item) return res.status(404).json({ message: 'Item not found' });

        item.name = req.body.name || item.name;
        item.quantity = req.body.quantity || item.quantity;
        item.price = req.body.price || item.price;

        const updatedItem = await item.save();
        res.json(updatedItem);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// DELETE inventory item
app.delete('/api/inventory/:id', async (req, res) => {
    try {
        const item = await Inventory.findByIdAndDelete(req.params.id);
        if (!item) return res.status(404).json({ message: 'Item not found' });
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Add this before other routes
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'healthy' });
});

// Configure CORS
app.use(cors({
  origin: 'https://farmanatura-inventario.onrender.com',
  credentials: true
}));