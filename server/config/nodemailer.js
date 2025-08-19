import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp-relay.brevo.com', // Brevo default
    port: Number(process.env.SMTP_PORT || 587),
    secure: false, // STARTTLS
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
    tls: {
        rejectUnauthorized: false, // helps on some corporate networks; safe for dev
    },
});

// Optional verification on startup in dev to surface config issues early
if (process.env.NODE_ENV !== 'production') {
    transporter.verify().then(() => {
        console.log('SMTP transporter verified and ready');
    }).catch((err) => {
        console.warn('SMTP verification failed:', err?.message || err);
    });
}

export default transporter;