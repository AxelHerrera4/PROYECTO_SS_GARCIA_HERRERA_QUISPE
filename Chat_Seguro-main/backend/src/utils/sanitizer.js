// Simple sanitizer utilities to prevent XSS and NoSQL injection
import validator from 'validator';

// Escape HTML entities and remove script tags
export const escapeHtml = (str = '') => {
  if (typeof str !== 'string') return str;
  // Remove script tags
  const noScript = str.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '');
  // Escape remaining HTML
  return validator.escape(noScript);
};

// Sanitize a single string (trim + escape)
export const sanitizeString = (str = '') => {
  if (typeof str !== 'string') return str;
  return escapeHtml(str.trim());
};

// Recursively sanitize an object (body/params/query)
export const sanitizeObject = (obj) => {
  if (!obj || typeof obj !== 'object') return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === 'string') {
      out[key] = sanitizeString(val);
    } else if (typeof val === 'object' && val !== null) {
      out[key] = sanitizeObject(val);
    } else {
      out[key] = val;
    }
  }
  return out;
};

export default { escapeHtml, sanitizeString, sanitizeObject };
