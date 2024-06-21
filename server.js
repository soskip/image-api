require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const multer = require('multer');
const sharp = require('sharp');
const cors = require('cors');

const app = express();
const upload = multer({ dest: 'uploads/' });
const PORT = process.env.PORT || 3000;
const OUTPUT_DIR = path.join(__dirname, 'converted');
const USERS_FILE = path.join(__dirname, 'users.json');

const SECRET = process.env.SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Middleware setup
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));

// Ensure output directory exists
if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Ensure users file exists
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

// Helper functions
const generateApiKey = () => jwt.sign({}, SECRET, { expiresIn: '1y' });

const authenticate = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

const isAdmin = (req, res, next) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.id === req.session.userId);
    if (!user || user.role !== 'admin') {
        return res.status(403).send('Access denied');
    }
    next();
};

// Create default admin account if it doesn't exist
const createDefaultAdmin = () => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const admin = users.find(user => user.username === 'admin');
    if (!admin) {
        const hashedPassword = bcrypt.hashSync('adminpassword', 8);
        const apiKey = generateApiKey();
        const adminUser = {
            id: Date.now().toString(),
            username: 'admin',
            password: hashedPassword,
            apiKey: apiKey,
            limit: 250,
            usage: 0,
            blocked: false,
            role: 'admin',
            lastUrlChange: null,
            lastReset: new Date().toISOString(),
        };
        users.push(adminUser);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        console.log('Default admin account created');
    }
};

createDefaultAdmin();

// Helper function to reset usage limits every month
const resetUsageLimits = () => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const currentDate = new Date();
    users.forEach(user => {
        const lastReset = new Date(user.lastReset);
        if ((currentDate - lastReset) / (1000 * 60 * 60 * 24) >= 30) {
            user.usage = 0;
            user.lastReset = currentDate.toISOString();
        }
    });
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// Run resetUsageLimits every time server starts
resetUsageLimits();

// Routes
app.get('/admin', authenticate, isAdmin, (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    res.render('admin', { users });
});

app.get('/user', authenticate, (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.id === req.session.userId);
    res.render('user', { user });
});

app.get('/status', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    console.log('Received /status request with API key:', apiKey);

    if (!apiKey) {
        return res.status(401).json({ error: 'No API key provided' });
    }

    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.apiKey === apiKey);

    if (!user) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    res.json({ usage: user.usage, limit: user.limit, blocked: user.blocked });
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);
    const apiKey = generateApiKey();

    const newUser = {
        id: Date.now().toString(),
        username: username,
        password: hashedPassword,
        apiKey: apiKey,
        limit: 250,
        usage: 0,
        blocked: false,
        role: 'user',
        lastUrlChange: null,
        lastReset: new Date().toISOString(),
    };

    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

    res.redirect('/login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.username === username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(400).json({ error: 'Invalid username or password' });
    }

    req.session.userId = user.id;
    if (user.role === 'admin') {
        res.redirect('/admin');
    } else {
        res.redirect('/user');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.delete('/user/:id', authenticate, isAdmin, (req, res) => {
    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    users = users.filter(user => user.id !== req.params.id);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.redirect('/admin');
});

app.post('/user/:id/block', authenticate, isAdmin, (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.id === req.params.id);
    user.blocked = !user.blocked;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.redirect('/admin');
});

app.post('/user/:id/update-limit', authenticate, isAdmin, (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.id === req.params.id);
    user.limit = req.body.limit;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.redirect('/admin');
});

app.post('/user/:id/generate-api-key', authenticate, isAdmin, (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.id === req.params.id);
    user.apiKey = generateApiKey();
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.redirect('/admin');
});

app.post('/convert', upload.single('image'), async (req, res) => {
    const apiKey = req.headers['x-api-key'];

    console.log(`Received /convert request with API key: ${apiKey}`);

    if (!apiKey) {
        return res.status(401).json({ error: 'No API key provided' });
    }

    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(user => user.apiKey === apiKey);

    if (!user) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    if (user.blocked) {
        return res.status(403).json({ error: 'API key is blocked' });
    }

    if (user.usage >= user.limit) {
        return res.status(403).json({ error: 'API key usage limit reached' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No image file provided' });
    }

    const inputPath = req.file.path;
    const fileName = path.parse(req.file.originalname).name; // Get the file name without extension
    const outputWebp = path.join(OUTPUT_DIR, `${fileName}.webp`);
    const outputAvif = path.join(OUTPUT_DIR, `${fileName}.avif`);

    try {
        console.log(`Starting conversion for ${inputPath}`);
        
        // Convert to WebP
        await sharp(inputPath)
            .webp({ quality: 80 })
            .toFile(outputWebp);

        console.log(`WebP conversion successful: ${outputWebp}`);

        // Convert to AVIF
        await sharp(inputPath)
            .avif({ quality: 50 })
            .toFile(outputAvif);

        console.log(`AVIF conversion successful: ${outputAvif}`);

        // Update usage count
        user.usage += 1;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        
        console.log(`User usage updated to: ${user.usage}`);

        // Send response before attempting to delete the file
        res.json({
            webp: `http://localhost:${PORT}/converted/${fileName}.webp`,
            avif: `http://localhost:${PORT}/converted/${fileName}.avif`,
        });

        // Ensure file is closed before attempting to delete it
        fs.closeSync(fs.openSync(inputPath, 'r'));

        // Add a delay before attempting to delete the file
        setTimeout(() => {
            fs.unlink(inputPath, (err) => {
                if (err) {
                    console.error(`Failed to remove original file: ${err.message}`);
                } else {
                    console.log(`Original file removed: ${inputPath}`);
                }
            });
        }, 100); // 100ms delay

    } catch (err) {
        console.error(`Image conversion failed: ${err.message}`);
        res.status(500).json({ error: 'Image conversion failed', details: err.message });
    }
});

// Authentication routes
app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
