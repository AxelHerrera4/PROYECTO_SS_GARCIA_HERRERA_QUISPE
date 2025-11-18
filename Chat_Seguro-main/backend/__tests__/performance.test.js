import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import User from '../src/models/User.js';
import Room from '../src/models/Room.js';

describe('Performance Tests', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Room.deleteMany({});
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Room.deleteMany({});
    await mongoose.connection.close();
  });

  describe('User Creation Performance', () => {
    test('should handle multiple user creations efficiently', async () => {
      const startTime = Date.now();
      const promises = [];

      // Crear 10 usuarios concurrentemente
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `user${i}`
          })
        );
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las respuestas sean exitosas
      results.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
      });

      // Verificar que tome menos de 5 segundos para 10 usuarios
      expect(duration).toBeLessThan(5000);

      console.log(`✅ 10 usuarios creados en ${duration}ms`);
    }, 10000);
  });

  describe('Room Creation Performance', () => {
    let token;

    beforeEach(async () => {
      const response = await request(app).post('/api/auth/login').send({
        nickname: 'admin'
      });
      token = response.body.token;
    });

    test('should handle multiple room creations efficiently', async () => {
      const startTime = Date.now();
      const promises = [];

      // Crear 5 salas concurrentemente
      for (let i = 0; i < 5; i++) {
        promises.push(
          request(app)
            .post('/api/rooms')
            .set('Authorization', `Bearer ${token}`)
            .send({
              name: `Sala ${i}`,
              type: 'texto'
            })
        );
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las respuestas sean exitosas
      results.forEach(response => {
        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('room');
      });

      // Verificar que tome menos de 3 segundos para 5 salas
      expect(duration).toBeLessThan(3000);

      console.log(`✅ 5 salas creadas en ${duration}ms`);
    }, 10000);
  });

  describe('Database Query Performance', () => {
    let token;

    beforeEach(async () => {
      const response = await request(app).post('/api/auth/login').send({
        nickname: 'admin'
      });
      token = response.body.token;

      // Crear 20 salas para testing
      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(
          request(app)
            .post('/api/rooms')
            .set('Authorization', `Bearer ${token}`)
            .send({
              name: `Sala ${i}`,
              type: 'texto'
            })
        );
      }
      await Promise.all(promises);
    });

    test('should retrieve rooms list efficiently', async () => {
      const startTime = Date.now();

      // Realizar 10 consultas concurrentes
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(request(app).get('/api/rooms'));
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las respuestas sean exitosas
      results.forEach(response => {
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
        expect(response.body.length).toBeGreaterThanOrEqual(20);
      });

      // Verificar que tome menos de 2 segundos para 10 consultas
      expect(duration).toBeLessThan(2000);

      console.log(`✅ 10 consultas de salas completadas en ${duration}ms`);
    }, 10000);
  });

  describe('Memory Usage Test', () => {
    test('should not have memory leaks in basic operations', async () => {
      const initialMemory = process.memoryUsage();

      // Realizar operaciones intensivas
      const promises = [];
      for (let i = 0; i < 50; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `testuser${i}`
          })
        );
      }

      await Promise.all(promises);

      // Forzar garbage collection si está disponible
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      // Verificar que el aumento de memoria no sea excesivo (< 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);

      console.log(`📊 Uso de memoria: ${Math.round(memoryIncrease / 1024 / 1024)}MB`);
    }, 30000);
  });
});
