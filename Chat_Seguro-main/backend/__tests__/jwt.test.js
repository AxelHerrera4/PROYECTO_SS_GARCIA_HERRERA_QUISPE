import { generateToken, verifyToken } from '../src/utils/jwt.js';

describe('JWT Utils', () => {
  describe('generateToken', () => {
    test('should generate a valid JWT token', () => {
      const payload = { id: '123', username: 'testuser' };
      const token = generateToken(payload);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    test('should include payload data in token', () => {
      const payload = { id: '456', username: 'admin' };
      const token = generateToken(payload);
      const decoded = verifyToken(token);
      
      expect(decoded.id).toBe(payload.id);
      expect(decoded.username).toBe(payload.username);
    });

    test('should set token expiration', () => {
      const payload = { id: '789' };
      const token = generateToken(payload);
      const decoded = verifyToken(token);
      
      expect(decoded.exp).toBeDefined();
      expect(decoded.iat).toBeDefined();
      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });
  });

  describe('verifyToken', () => {
    test('should verify valid token', () => {
      const payload = { id: '123', username: 'testuser' };
      const token = generateToken(payload);
      const decoded = verifyToken(token);
      
      expect(decoded).toBeDefined();
      expect(decoded.id).toBe('123');
      expect(decoded.username).toBe('testuser');
    });

    test('should throw error for invalid token', () => {
      const invalidToken = 'invalid.token.here';
      expect(() => verifyToken(invalidToken)).toThrow();
    });

    test('should throw error for malformed token', () => {
      const malformedToken = 'not-a-jwt-token';
      expect(() => verifyToken(malformedToken)).toThrow();
    });

    test('should throw error for empty token', () => {
      expect(() => verifyToken('')).toThrow();
    });

    test('should throw error for null token', () => {
      expect(() => verifyToken(null)).toThrow();
    });
  });
});
