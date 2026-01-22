const rawJwtSecret = process.env.JWT_SECRET;
if (!rawJwtSecret || rawJwtSecret.trim() === '') {
  console.error('JWT_SECRET is required and must be non-empty.');
  process.exit(1);
}

const JWT_SECRET = rawJwtSecret;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

export { JWT_SECRET, JWT_EXPIRES_IN };
