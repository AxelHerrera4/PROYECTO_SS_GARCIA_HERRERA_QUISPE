import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import User from '../src/models/User.js';
import Room from '../src/models/Room.js';

describe('Stress Tests', () => {
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

  describe('Extreme Load Scenarios', () => {
    test('should handle 100 concurrent user logins', async () => {
      const startTime = Date.now();
      const promises = [];

      // Crear 100 usuarios concurrentemente
      for (let i = 0; i < 100; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `stressuser${i}`
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

      // Verificar que tome menos de 15 segundos para 100 usuarios
      expect(duration).toBeLessThan(15000);

      console.log(`🚀 100 usuarios concurrentes logueados en ${duration}ms`);
    }, 60000);

    test('should handle 500 sequential operations', async () => {
      const startTime = Date.now();

      // Operaciones secuenciales para evitar sobrecarga extrema
      for (let i = 0; i < 500; i++) {
        const response = await request(app).post('/api/auth/login').send({
          nickname: `seqstress${i}`
        });
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que tome menos de 60 segundos para 500 operaciones
      expect(duration).toBeLessThan(60000);

      console.log(`🔄 500 operaciones secuenciales completadas en ${duration}ms`);
    }, 120000);
  });

  describe('Database Stress Under Load', () => {
    test('should handle 1000 room queries efficiently', async () => {
      // Preparar datos: crear 100 salas
      const tokenResponse = await request(app).post('/api/auth/login').send({
        nickname: 'querymaster'
      });
      const token = tokenResponse.body.token;

      const createPromises = [];
      for (let i = 0; i < 100; i++) {
        createPromises.push(
          request(app)
            .post('/api/rooms')
            .set('Authorization', `Bearer ${token}`)
            .send({
              name: `Stress Room ${i}`,
              type: 'texto'
            })
        );
      }
      await Promise.all(createPromises);

      // Ahora hacer 1000 consultas concurrentes
      const startTime = Date.now();
      const queryPromises = [];
      for (let i = 0; i < 1000; i++) {
        queryPromises.push(request(app).get('/api/rooms'));
      }

      const results = await Promise.all(queryPromises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las consultas sean exitosas
      results.forEach(response => {
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
        expect(response.body.length).toBeGreaterThanOrEqual(100);
      });

      // Verificar que tome menos de 30 segundos para 1000 consultas
      expect(duration).toBeLessThan(30000);

      console.log(`🔍 1000 consultas de BD completadas en ${duration}ms`);
    }, 120000);
  });

  describe('Memory Stress Test Extreme', () => {
    test('should handle extreme sustained load without crashing', async () => {
      const initialMemory = process.memoryUsage();
      const operations = 1000;

      // Realizar operaciones intensivas de manera muy sostenida
      for (let batch = 0; batch < 10; batch++) {
        const promises = [];
        for (let i = 0; i < 100; i++) {
          const userIndex = batch * 100 + i;
          promises.push(
            request(app).post('/api/auth/login').send({
              nickname: `extremestress${userIndex}`
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

      // Verificar que el aumento de memoria no sea excesivo (< 200MB)
      expect(memoryIncrease).toBeLessThan(200 * 1024 * 1024);

      console.log(`🧠 Test de estrés extremo completado. Aumento de memoria: ${Math.round(memoryIncrease / 1024 / 1024)}MB`);
    }, 300000);
  });

  describe('Concurrent Operations Stress', () => {
    test('should handle 200 concurrent mixed operations', async () => {
      const startTime = Date.now();
      const promises = [];

      // Crear algunos usuarios primero para tener tokens
      const userPromises = [];
      for (let i = 0; i < 20; i++) {
        userPromises.push(
          request(app).post('/api/auth/login').send({
            nickname: `concurrentuser${i}`
          })
        );
      }
      const userResults = await Promise.all(userPromises);
      const tokens = userResults.map(r => r.body.token);

      // 100 operaciones de login
      for (let i = 0; i < 100; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `mixedstress${i}`
          })
        );
      }

      // 100 operaciones de consulta de salas
      for (let i = 0; i < 100; i++) {
        promises.push(request(app).get('/api/rooms'));
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verificar que todas las operaciones sean exitosas
      results.forEach(response => {
        expect([200, 201]).toContain(response.status);
      });

      // Verificar que tome menos de 20 segundos
      expect(duration).toBeLessThan(20000);

      console.log(`🔀 200 operaciones mixtas concurrentes completadas en ${duration}ms`);
    }, 60000);
  });

  describe('Error Handling Under Stress', () => {
    test('should handle invalid requests under load gracefully', async () => {
      const startTime = Date.now();
      const promises = [];

      // 50 operaciones válidas
      for (let i = 0; i < 50; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: `validstress${i}`
          })
        );
      }

      // 50 operaciones inválidas (nickname vacío)
      for (let i = 0; i < 50; i++) {
        promises.push(
          request(app).post('/api/auth/login').send({
            nickname: ''
          })
        );
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      let validCount = 0;
      let invalidCount = 0;

      results.forEach(response => {
        if (response.status === 200) {
          validCount++;
        } else if (response.status === 400) {
          invalidCount++;
        }
      });

      // Verificar que tengamos respuestas válidas e inválidas
      expect(validCount).toBeGreaterThan(40);
      expect(invalidCount).toBeGreaterThan(40);

      // Verificar que tome menos de 10 segundos
      expect(duration).toBeLessThan(10000);

      console.log(`⚠️ Test de manejo de errores bajo estrés: ${validCount} válidas, ${invalidCount} inválidas en ${duration}ms`);
    }, 30000);
  });
});
