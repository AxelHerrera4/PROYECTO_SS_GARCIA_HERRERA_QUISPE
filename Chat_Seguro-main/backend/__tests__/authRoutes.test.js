import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import User from '../src/models/User.js';

describe('Auth Routes', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/auth/register', () => {
    test('should register a new user successfully', async () => {
      const newUser = {
        name: 'Test User',
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(newUser)
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('username', 'testuser');
      expect(response.body).toHaveProperty('email', 'test@example.com');
      expect(response.body).not.toHaveProperty('password');
    });

    test('should reject registration with duplicate username', async () => {
      const user = {
        name: 'First User',
        username: 'duplicate',
        email: 'first@example.com',
        password: 'password123',
      };

      await request(app).post('/api/auth/register').send(user);

      const duplicate = {
        name: 'Second User',
        username: 'duplicate',
        email: 'second@example.com',
        password: 'password456',
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(duplicate)
        .expect(400);

      expect(response.body).toHaveProperty('message');
    });

    test('should reject registration with duplicate email', async () => {
      const user = {
        name: 'First User',
        username: 'firstuser',
        email: 'duplicate@example.com',
        password: 'password123',
      };

      await request(app).post('/api/auth/register').send(user);

      const duplicate = {
        name: 'Second User',
        username: 'seconduser',
        email: 'duplicate@example.com',
        password: 'password456',
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(duplicate)
        .expect(400);

      expect(response.body).toHaveProperty('message');
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await request(app).post('/api/auth/register').send({
        name: 'Test User',
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      });
    });

    test('should login with valid username and password', async () => {
      const credentials = {
        identifier: 'testuser',
        password: 'password123',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('username', 'testuser');
      expect(response.body).not.toHaveProperty('password');
    });

    test('should login with valid email and password', async () => {
      const credentials = {
        identifier: 'test@example.com',
        password: 'password123',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('email', 'test@example.com');
    });

    test('should reject login with invalid password', async () => {
      const credentials = {
        identifier: 'testuser',
        password: 'wrongpassword',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(401);

      expect(response.body).toHaveProperty('message');
    });

    test('should reject login with non-existent username', async () => {
      const credentials = {
        identifier: 'nonexistent',
        password: 'password123',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(401);

      expect(response.body).toHaveProperty('message');
    });
  });
});
