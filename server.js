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
app.use('/api/submit-company', limiter);
app.use('/api/submit-fleet-worker', limiter);

app.use(express.json({ limit: '10kb' })); // Body parser with size limit

// Email transporter configuration
const transporter = nodemailer.createTransporter({
    host: 'mail.spacemail.com', // Replace with the actual SMTP host for spacemail
    port: 465, // Replace with the actual port for spacemail
    secure: true, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});

// Validation middlewares

const validateCompanyRequest = [
    body('companyName').trim().notEmpty().withMessage('Company name is required')
        .isLength({ min: 2, max: 100 }).withMessage('Company name must be between 2 and 100 characters'),
    body('email').trim().isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
    body('phone').trim().matches(/^\+?[\d\s-]{10,}$/).withMessage('Valid phone number is required'),
    body('firstName').trim().notEmpty().withMessage('First name is required'),
    body('lastName').trim().notEmpty().withMessage('Last name is required'),
    body('cityProvince').trim().notEmpty().withMessage('City & Province is required'),
    body('majorArea').trim().notEmpty().withMessage('Major area is required'),
    body('details').trim().isLength({ max: 1000 }).withMessage('Details must not exceed 1000 characters')
];

const validateFleetWorkerRequest = [
    body('firstName').trim().notEmpty().withMessage('First name is required')
        .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
    body('lastName').trim().notEmpty().withMessage('Last name is required')
        .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
    body('email').trim().isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
    body('phone').trim().matches(/^\+?[\d\s-]{10,}$/).withMessage('Valid phone number is required'),
    body('city').trim().notEmpty().withMessage('City is required')
        .isLength({ min: 2, max: 100 }).withMessage('City must be between 2 and 100 characters'),
    body('specialtyCategory').trim().notEmpty().withMessage('Specialty category is required'),
    body('specialtySubcategory').trim().notEmpty().withMessage('Specialty subcategory is required'),
    body('yearsOfExperience').trim().notEmpty().withMessage('Years of experience is required'),
    body('cdlLicense').optional().trim().isLength({ max: 100 }).withMessage('CDL license must not exceed 100 characters'),
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

// Fleet Worker Application Endpoint
app.post('/api/submit-fleet-worker', validateFleetWorkerRequest, async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { 
            firstName, lastName, email, phone, city,
            specialtyCategory, specialtySubcategory, 
            yearsOfExperience, cdlLicense, details 
        } = req.body;

        // Map specialty categories for display
        const specialtyCategories = {
            'A': 'Management & Operations',
            'B': 'Technical & Maintenance Jobs',
            'C': 'Snow & Wind Services',
            'D': 'Fleet Vehicle Operator Roles',
            'E': 'Fleet Drivers & Other Support Jobs'
        };

        const categoryLabel = specialtyCategories[specialtyCategory] || specialtyCategory;

        // Email to admin
        const adminMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
            subject: 'New Fleet Worker Application',
            replyTo: email,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #b35c0d;">New Fleet Worker Application</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p><strong>Name:</strong> ${firstName} ${lastName}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Phone:</strong> ${phone}</p>
                        <p><strong>City:</strong> ${city}</p>
                        <p><strong>Specialty Category:</strong> ${specialtyCategory} - ${categoryLabel}</p>
                        <p><strong>Specific Specialty:</strong> ${specialtySubcategory}</p>
                        <p><strong>Years of Experience:</strong> ${yearsOfExperience}</p>
                        ${cdlLicense ? `<p><strong>CDL License:</strong> ${cdlLicense}</p>` : ''}
                        <h3>Additional Details:</h3>
                        <p style="white-space: pre-wrap;">${details || 'No additional details provided'}</p>
                    </div>
                </div>
            `
        };

        // Email to fleet worker
        const workerMailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Fleet Worker Application Received',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #b35c0d;">Thank you for your application!</h2>
                    <p>Dear ${firstName} ${lastName},</p>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p>We have received your fleet worker application from ${city} and will review it shortly. 
                           Our team will contact you within 2-3 business days.</p>
                        
                        <h3>Application Summary:</h3>
                        <p><strong>Location:</strong> ${city}</p>
                        <p><strong>Specialty:</strong> ${categoryLabel}</p>
                        <p><strong>Specific Role:</strong> ${specialtySubcategory}</p>
                        <p><strong>Experience:</strong> ${yearsOfExperience} years</p>
                        ${cdlLicense ? `<p><strong>License:</strong> ${cdlLicense}</p>` : ''}
                    </div>
                    <p>If you have any questions, please don't hesitate to contact us.</p>
                    <p>Best regards,<br>Fleet Armor Team</p>
                </div>
            `
        };

        await Promise.all([
            transporter.sendMail(adminMailOptions),
            transporter.sendMail(workerMailOptions)
        ]);

        logger.info('Fleet worker application submitted successfully', {
            name: `${firstName} ${lastName}`,
            email: email,
            city: city,
            specialty: specialtySubcategory,
            timestamp: new Date().toISOString()
        });

        res.status(200).json({ 
            message: 'Fleet worker application submitted successfully',
            status: 'success'
        });

    } catch (error) {
        next(error);
    }
});

// Company Request Endpoint (for fleet companies)
app.post('/api/submit-company', validateCompanyRequest, async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { 
            companyName, firstName, lastName, email, phone, 
            cityProvince, majorArea, details 
        } = req.body;

        // Email to admin
        const adminMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
            subject: 'New Fleet Company Request',
            replyTo: email,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #b35c0d;">New Fleet Company Request</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p><strong>Company:</strong> ${companyName}</p>
                        <p><strong>Contact Person:</strong> ${firstName} ${lastName}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Phone:</strong> ${phone}</p>
                        <p><strong>Location:</strong> ${cityProvince}</p>
                        <p><strong>Major Area of Interest:</strong> ${majorArea}</p>
                        <h3>Additional Details:</h3>
                        <p style="white-space: pre-wrap;">${details || 'No additional details provided'}</p>
                    </div>
                </div>
            `
        };

        // Email to company
        const companyMailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Fleet Service Request Received',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #b35c0d;">Thank you for your fleet service request!</h2>
                    <p>Dear ${firstName} ${lastName},</p>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <p>We have received your fleet service request for ${companyName} and will review it shortly. 
                           Our team will contact you within 24-48 hours.</p>
                        
                        <h3>Request Summary:</h3>
                        <p><strong>Company:</strong> ${companyName}</p>
                        <p><strong>Location:</strong> ${cityProvince}</p>
                        <p><strong>Area of Interest:</strong> ${majorArea}</p>
                    </div>
                    <p>If you have any immediate questions, please don't hesitate to contact us.</p>
                    <p>Best regards,<br>Fleet Armor Team</p>
                </div>
            `
        };

        await Promise.all([
            transporter.sendMail(adminMailOptions),
            transporter.sendMail(companyMailOptions)
        ]);

        logger.info('Fleet company request submitted successfully', {
            company: companyName,
            contact: `${firstName} ${lastName}`,
            email: email,
            majorArea: majorArea,
            timestamp: new Date().toISOString()
        });

        res.status(200).json({ 
            message: 'Company request submitted successfully',
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
        timestamp: new Date().toISOString(),
        endpoints: [
            '/api/submit-fleet-worker',
            '/api/submit-company',
        ]
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
    logger.info('Available endpoints:');
    logger.info('  POST /api/submit-fleet-worker');
    logger.info('  POST /api/submit-company');
    logger.info('  GET  /api/health');
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
        logger.info('Process terminated');
    });
});