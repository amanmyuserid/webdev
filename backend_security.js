const express = require('express');
const helmet = require('helmet');
const xssClean = require('xss-clean');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const compression = require('compression');
const hpp = require('hpp'); // Prevent HTTP parameter pollution
const mongoSanitize = require('express-mongo-sanitize'); // Prevent NoSQL injection
const path = require('path'); // For directory traversal protection

const app = express();

// Middleware for security enhancements
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
        },
    },
})); // Secure HTTP headers

app.use(xssClean()); // Prevent XSS attacks
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(hpp()); // Prevent HTTP parameter pollution
app.use(compression()); // Compress responses to improve performance
app.use(express.json({ limit: '10kb', strict: true })); // Limit payload size and enforce strict JSON parsing
app.use(cookieParser()); // Parse cookies

// Logging with Winston
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console(),
    ],
});

// Rate Limiter Configuration
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many requests, please try again later.',
    handler: (req, res, next, options) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).send(options.message);
    },
});
app.use(limiter);

// CORS configuration
const corsOptions = {
    origin: 'https://yourdomain.com', // Replace with your frontend domain
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true, // Allow cookies
};
app.use(cors(corsOptions));

// CSRF protection
const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

// Static file serving with security
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'deny' }));

// Cache control for sensitive data
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// Simulate a user database
const users = [];

// Register route
app.post('/register',
    [
        body('username').isAlphanumeric().withMessage('Username must be alphanumeric'),
        body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        try {
            const hashedPassword = await argon2.hash(password);
            users.push({ username, password: hashedPassword });
            logger.info(`User registered: ${username}`);
            res.status(201).send('User registered successfully!');
        } catch (err) {
            logger.error('Error hashing password:', err);
            res.status(500).send('Internal server error');
        }
    });

// Login route
app.post('/login',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(401).send('Invalid username or password');
        }

        try {
            const isValid = await argon2.verify(user.password, password);
            if (isValid) {
                res.cookie('sessionId', 'some-secure-token', {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'Strict',
                });
                logger.info(`User logged in: ${username}`);
                res.send('Login successful!');
            } else {
                res.status(401).send('Invalid username or password');
            }
        } catch (err) {
            logger.error('Error verifying password:', err);
            res.status(500).send('Internal server error');
        }
    });

// Protected route
app.post('/protected', csrfProtection, (req, res) => {
    res.status(200).send('Access granted to protected resource.');
});

app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});


// Error handling middleware 
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        logger.warn(`CSRF token validation failed for IP: ${req.ip}`);
        return res.status(403).send('CSRF token validation failed.');
    }
    logger.error('Unexpected error:', err);
    res.status(500).send('Internal server error');
});

// Request timeout to prevent long-running requests
app.use((req, res, next) => {
    req.setTimeout(10000, () => res.status(408).send('Request Timeout'));
    next();
});

app.listen(3000, () => console.log('Server running on port 3000'));
