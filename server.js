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

// Add these validation middlewares after the existing validateQuoteRequest
const validateGuardRequest = [
    body('fullName').trim().notEmpty().withMessage('Full name is required')
        .isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
    body('email').trim().isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
    body('phone').trim().matches(/^\+?[\d\s-]{10,}$/).withMessage('Valid phone number is required'),
    body('city').trim().notEmpty().withMessage('City is required'),
    body('license').trim().notEmpty().withMessage('Security guard license is required'),
    body('yearsOfExperience').trim().notEmpty().withMessage('Years of experience is required'),
    body('details').trim().isLength({ max: 1000 }).withMessage('Details must not exceed 1000 characters')
];

const validateCompanyRequest = [
    body('companyName').trim().notEmpty().withMessage('Company name is required')
        .isLength({ min: 2, max: 100 }).withMessage('Company name must be between 2 and 100 characters'),
    body('email').trim().isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
    body('phone').trim().matches(/^\+?[\d\s-]{10,}$/).withMessage('Valid phone number is required'),
    body('firstName').trim().notEmpty().withMessage('First name is required'),
    body('lastName').trim().notEmpty().withMessage('Last name is required'),
    body('city').trim().notEmpty().withMessage('City is required'),
    body('securityGuardType').trim().notEmpty().withMessage('Security guard type is required'),
    body('numberOfGuards').trim().notEmpty().withMessage('Number of guards is required'),
    body('service').trim().notEmpty().withMessage('Service type is required'),
    body('details').trim().isLength({ max: 1000 }).withMessage('Details must not exceed 1000 characters')
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


app.post('/api/submit-guard', validateGuardRequest, async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { fullName, email, phone, city, license, yearsOfExperience, details } = req.body;

        const transporter = createTransporter();

        // Email to admin
        const adminMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
            subject: 'New Security Guard Application',
            replyTo: email,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">New Security Guard Application</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p><strong>Full Name:</strong> ${fullName}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Phone:</strong> ${phone}</p>
                        <p><strong>City:</strong> ${city}</p>
                        <p><strong>License:</strong> ${license}</p>
                        <p><strong>Years of Experience:</strong> ${yearsOfExperience}</p>
                        <h3>Additional Details:</h3>
                        <p style="white-space: pre-wrap;">${details}</p>
                    </div>
                </div>
            `
        };

        // Email to applicant
        const applicantMailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Application Received - GuardArmor Security',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Thank you for your application!</h2>
                    <p>Dear ${fullName},</p>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p>We have received your security guard application and will review it shortly. 
                           Our team will contact you within 2-3 business days.</p>
                        
                        <h3>Application Details:</h3>
                        <p><strong>License:</strong> ${license}</p>
                        <p><strong>Years of Experience:</strong> ${yearsOfExperience}</p>
                        <p><strong>City:</strong> ${city}</p>
                    </div>
                    <p>If you have any questions, please don't hesitate to contact us.</p>
                    <p>Best regards,<br>Guard Armor Team</p>
                </div>
            `
        };

        await Promise.all([
            transporter.sendMail(adminMailOptions),
            transporter.sendMail(applicantMailOptions)
        ]);

        logger.info('Guard application submitted successfully', {
            email: email,
            timestamp: new Date().toISOString()
        });

        res.status(200).json({ 
            message: 'Application submitted successfully',
            status: 'success'
        });

    } catch (error) {
        next(error);
    }
});

app.post('/api/submit-company', validateCompanyRequest, async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { 
            companyName, email, phone, firstName, lastName, 
            city, securityGuardType, numberOfGuards, service, details 
        } = req.body;

        const transporter = createTransporter();

        // Email to admin
        const adminMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
            subject: 'New Company Security Request',
            replyTo: email,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">New Company Security Request</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p><strong>Company:</strong> ${companyName}</p>
                        <p><strong>Contact:</strong> ${firstName} ${lastName}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Phone:</strong> ${phone}</p>
                        <p><strong>City:</strong> ${city}</p>
                        <p><strong>Security Guard Type:</strong> ${securityGuardType}</p>
                        <p><strong>Number of Guards:</strong> ${numberOfGuards}</p>
                        <p><strong>Service Type:</strong> ${service}</p>
                        <h3>Additional Details:</h3>
                        <p style="white-space: pre-wrap;">${details}</p>
                    </div>
                </div>
            `
        };

        // Email to company
        const companyMailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Security Service Request Received - Guard Armor',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Thank you for your security service request!</h2>
                    <p>Dear ${firstName} ${lastName},</p>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p>We have received your security service request for ${companyName} and will review it shortly. 
                           Our team will contact you within 24-48 business hours.</p>
                        
                        <h3>Request Details:</h3>
                        <p><strong>Security Guard Type:</strong> ${securityGuardType}</p>
                        <p><strong>Number of Guards:</strong> ${numberOfGuards}</p>
                        <p><strong>Service Type:</strong> ${service}</p>
                        <p><strong>City:</strong> ${city}</p>
                    </div>
                    <p>If you have any immediate questions, please don't hesitate to contact us.</p>
                    <p>Best regards,<br>Guard Armor Team</p>
                </div>
            `
        };

        await Promise.all([
            transporter.sendMail(adminMailOptions),
            transporter.sendMail(companyMailOptions)
        ]);

        logger.info('Company request submitted successfully', {
            company: companyName,
            email: email,
            timestamp: new Date().toISOString()
        });

        res.status(200).json({ 
            message: 'Request submitted successfully',
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