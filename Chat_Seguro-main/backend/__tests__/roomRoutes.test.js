import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import Room from '../src/models/Room.js';
import User from '../src/models/User.js';

describe('Room Routes', () => {
  let token;
  let userId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await Room.deleteMany({});
    await User.deleteMany({});

    const response = await request(app).post('/api/auth/register').send({
      name: 'Test User',
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
    });
    token = response.body.token;
    userId = response.body._id;
  });

  afterAll(async () => {
    await Room.deleteMany({});
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/rooms', () => {
    test('should reject room creation without authentication', async () => {
      const roomData = {
        name: 'Test Room',
        type: 'public',
      };

      await request(app)
        .post('/api/rooms')
        .send(roomData)
        .expect(401);
    });
  });

  describe('GET /api/rooms', () => {
    test('should return empty array when no rooms exist', async () => {
      const response = await request(app)
        .get('/api/rooms')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBe(0);
    });
  });

  describe('GET /api/rooms/:id', () => {
    test('should return 404 for non-existent room', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      await request(app)
        .get(`/api/rooms/${fakeId}`)
        .expect(404);
    });
  });
});
