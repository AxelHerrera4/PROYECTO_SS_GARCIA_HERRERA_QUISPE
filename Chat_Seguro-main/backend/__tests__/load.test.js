import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import User from '../src/models/User.js';
import Room from '../src/models/Room.js';

describe('Load Tests', () => {
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

  describe('High Load User Operations', () => {
    test('should handle 50 concurrent user logins', async () => {
      const startTime = Date.now();
      const promises = [];

      // Crear 50 usuarios concurrentemente
      for (let i = 0; i < 50; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `loaduser${i}`
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

      // Verificar que tome menos de 10 segundos para 50 usuarios
      expect(duration).toBeLessThan(10000);

      console.log(`🚀 50 usuarios concurrentes logueados en ${duration}ms`);
    }, 30000);

    test('should handle 100 sequential user operations', async () => {
      const startTime = Date.now();

      // Operaciones secuenciales para evitar sobrecarga de DB
      for (let i = 0; i < 100; i++) {
        const response = await request(app).post('/api/auth/login').send({
          nickname: `sequser${i}`
        });
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que tome menos de 30 segundos para 100 operaciones
      expect(duration).toBeLessThan(30000);

      console.log(`🔄 100 operaciones secuenciales completadas en ${duration}ms`);
    }, 60000);
  });

  describe('High Load Room Operations', () => {
    let tokens = [];

    beforeEach(async () => {
      // Crear 10 usuarios para tener tokens disponibles
      for (let i = 0; i < 10; i++) {
        const response = await request(app).post('/api/auth/login').send({
          nickname: `roomuser${i}`
        });
        tokens.push(response.body.token);
      }
    });

    test('should handle 25 concurrent room creations', async () => {
      const startTime = Date.now();
      const promises = [];

      // Crear 25 salas concurrentemente usando diferentes tokens
      for (let i = 0; i < 25; i++) {
        const token = tokens[i % tokens.length];
        promises.push(
          request(app)
            .post('/api/rooms')
            .set('Authorization', `Bearer ${token}`)
            .send({
              name: `Load Room ${i}`,
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

      // Verificar que tome menos de 15 segundos para 25 salas
      expect(duration).toBeLessThan(15000);

      console.log(`🏠 25 salas concurrentes creadas en ${duration}ms`);
    }, 30000);
  });

  describe('Database Stress Test', () => {
    test('should handle 200 room queries efficiently', async () => {
      // Preparar datos: crear 50 salas
      const tokenResponse = await request(app).post('/api/auth/login').send({
        nickname: 'queryuser'
      });
      const token = tokenResponse.body.token;

      const createPromises = [];
      for (let i = 0; i < 50; i++) {
        createPromises.push(
          request(app)
            .post('/api/rooms')
            .set('Authorization', `Bearer ${token}`)
            .send({
              name: `Query Room ${i}`,
              type: 'texto'
            })
        );
      }
      await Promise.all(createPromises);

      // Ahora hacer 200 consultas concurrentes
      const startTime = Date.now();
      const queryPromises = [];
      for (let i = 0; i < 200; i++) {
        queryPromises.push(request(app).get('/api/rooms'));
      }

      const results = await Promise.all(queryPromises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las consultas sean exitosas
      results.forEach(response => {
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
        expect(response.body.length).toBeGreaterThanOrEqual(50);
      });

      // Verificar que tome menos de 20 segundos para 200 consultas
      expect(duration).toBeLessThan(20000);

      console.log(`🔍 200 consultas de BD completadas en ${duration}ms`);
    }, 60000);
  });

  describe('Memory Stress Test', () => {
    test('should handle sustained load without memory leaks', async () => {
      const initialMemory = process.memoryUsage();
      const operations = 200;

      // Realizar operaciones intensivas de manera sostenida
      for (let batch = 0; batch < 4; batch++) {
        const promises = [];
        for (let i = 0; i < 50; i++) {
          const userIndex = batch * 50 + i;
          promises.push(
            request(app).post('/api/auth/login').send({
              nickname: `stressuser${userIndex}`
            })
          );
        }
        await Promise.all(promises);

        // Forzar garbage collection si está disponible
        if (global.gc) {
          global.gc();
        }
      }

      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      // Verificar que el aumento de memoria no sea excesivo (< 100MB)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);

      console.log(`🧠 Test de estrés completado. Aumento de memoria: ${Math.round(memoryIncrease / 1024 / 1024)}MB`);
    }, 120000);
  });

  describe('Concurrent Mixed Operations', () => {
    test('should handle mixed concurrent operations', async () => {
      const startTime = Date.now();
      const promises = [];

      // 20 operaciones de login
      for (let i = 0; i < 20; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `mixeduser${i}`
          })
        );
      }

      // 10 operaciones de consulta de salas
      for (let i = 0; i < 10; i++) {
        promises.push(request(app).get('/api/rooms'));
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las operaciones sean exitosas
      results.forEach(response => {
        expect([200, 201]).toContain(response.status);
      });

      // Verificar que tome menos de 10 segundos
      expect(duration).toBeLessThan(10000);

      console.log(`🔀 30 operaciones mixtas concurrentes completadas en ${duration}ms`);
    }, 30000);
  });
});
