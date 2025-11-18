import { generatePIN } from '../src/utils/pinGenerator.js';

describe('PIN Generator', () => {
  describe('generatePIN', () => {
    test('should generate a 4-digit PIN', () => {
      const pin = generatePIN();
      expect(pin).toHaveLength(4);
      expect(pin).toMatch(/^\d{4}$/);
    });

    test('should generate numeric PIN only', () => {
      const pin = generatePIN();
      const num = parseInt(pin, 10);
      expect(num).toBeGreaterThanOrEqual(1000);
      expect(num).toBeLessThanOrEqual(9999);
    });

    test('should generate different PINs on multiple calls', () => {
      const pins = new Set();
      for (let i = 0; i < 20; i++) {
        pins.add(generatePIN());
      }
      // Probabilidad muy alta de tener al menos 15 PINs diferentes en 20 intentos
      expect(pins.size).toBeGreaterThanOrEqual(15);
    });

    test('should not generate PIN starting with 0', () => {
      for (let i = 0; i < 10; i++) {
        const pin = generatePIN();
        expect(pin[0]).not.toBe('0');
      }
    });
  });
});
