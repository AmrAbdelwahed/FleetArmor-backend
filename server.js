const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const winston = require('winston');
const { body, validationResult } = require('express-validator');

// Load environment variables
dotenv.config();

console.log('Email configuration:', {
    service: process.env.EMAIL_SERVICE,
    user: process.env.EMAIL_USER,
    // Don't log the actual password
    hasPassword: !!process.env.EMAIL_APP_PASSWORD
})

// Configure Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

const app = express();

// Security Middleware
app.use(helmet()); // Adds various HTTP headers for security
app.use(xss()); // Sanitize input
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    methods: ['POST', 'GET'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/submit-quote', limiter);

app.use(express.json({ limit: '10kb' })); // Body parser with size limit

// Email transporter configuration
const createTransporter = () => {
    return nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_APP_PASSWORD
        }
    });
};

// Input validation middleware
const validateQuoteRequest = [
    body('name').trim().notEmpty().withMessage('Name is required')
        .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
    body('email').trim().isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
    body('phone').trim().matches(/^\+?[\d\s-]{10,}$/).withMessage('Valid phone number is required'),
    body('details').trim().notEmpty().withMessage('Details are required')
        .isLength({ max: 1000 }).withMessage('Details must not exceed 1000 characters'),
    body('company').trim().optional().isLength({ max: 100 })
];

// Error handling middleware
const errorHandler = (err, req, res, next) => {
    logger.error('Error:', {
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method
    });

    res.status(err.status || 500).json({
        error: process.env.NODE_ENV === 'production' 
            ? 'An error occurred' 
            : err.message
    });
};

// Quote submission endpoint
app.post('/api/submit-quote', validateQuoteRequest, async (req, res, next) => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, phone, company, details } = req.body;

        const transporter = createTransporter();

        // Email templates
        const adminMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,  // Fallback to EMAIL_USER if ADMIN_EMAIL is not set
            subject: 'New Quote Request',
            replyTo: email, // Customer's email for replies
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">New Quote Request</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p><strong>Name:</strong> ${name}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Phone:</strong> ${phone}</p>
                        ${company ? `<p><strong>Company:</strong> ${company}</p>` : ''}
                        <h3>Details:</h3>
                        <p style="white-space: pre-wrap;">${details}</p>
                    </div>
                </div>
            `
        };

        const customerMailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quote Request Received - Guard Armor',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Thank you for your quote request!</h2>
                    <p>Dear ${name},</p>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p>We have received your quote request and will review it shortly. 
                           Our team will get back to you within 24-48 business hours.</p>
                        
                        <h3>Your Request Details:</h3>
                        <p><strong>Phone:</strong> ${phone}</p>
                        ${company ? `<p><strong>Company:</strong> ${company}</p>` : ''}
                        <p><strong>Details:</strong></p>
                        <p style="white-space: pre-wrap;">${details}</p>
                    </div>
                    <p>If you have any immediate questions, please don't hesitate to contact us.</p>
                    <p>Best regards,<br>Guard Armor Team</p>
                </div>
            `
        };

        // Send emails
        await Promise.all([
            transporter.sendMail(adminMailOptions),
            transporter.sendMail(customerMailOptions)
        ]);

        logger.info('Quote submitted successfully', {
            email: email,
            timestamp: new Date().toISOString()
        });

        res.status(200).json({ 
            message: 'Quote submitted successfully',
            status: 'success'
        });

    } catch (error) {
        next(error);
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

// Apply error handling middleware
app.use(errorHandler);

// Handle unhandled routes
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3001;

// Graceful shutdown handling
const server = app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
        logger.info('Process terminated');
    });
});