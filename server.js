// server.js
const Hapi = require('@hapi/hapi');
const HapiAuthJwt2 = require('hapi-auth-jwt2');
const JWT = require('jsonwebtoken');

// Ganti secret dengan environment variables pada produksi
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'replace_this_access_secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'replace_this_refresh_secret';

// Simple in-memory stores (demo). Ganti dengan DB/Redis pada produksi.
const users = new Map(); // mock "users table"
const refreshTokenStore = new Map(); // map<refreshToken, userId>

// contoh user
users.set('1', { id: '1', username: 'alice', role: 'user' });

/**
 * Hapi validation function untuk hapi-auth-jwt2
 * decoded = payload hasil decode JWT (sudah diverifikasi signature oleh plugin)
 */
const validate = async (decoded, request, h) => {
  const userId = decoded.sub;
  const user = users.get(userId);
  if (!user) {
    // invalid => unauthorized
    return { isValid: false };
  }
  // bisa cek kondisi lain: user.active, token blacklist, dsb.
  return { isValid: true, credentials: user }; // credentials akan tersedia di request.auth.credentials
};

const signAccessToken = (userId, opts = {}) => {
  return JWT.sign({ sub: userId }, ACCESS_TOKEN_SECRET, {
    algorithm: 'HS256',
    expiresIn: opts.expiresIn || '15m'
  });
};

const signRefreshToken = (userId, opts = {}) => {
  return JWT.sign({ sub: userId }, REFRESH_TOKEN_SECRET, {
    algorithm: 'HS256',
    expiresIn: opts.expiresIn || '7d'
  });
};

const createServer = async () => {
  const server = Hapi.server({ port: process.env.PORT || 3000, host: 'localhost' });

  // register plugin
  await server.register(HapiAuthJwt2);

  // definisikan strategy
  server.auth.strategy('jwt', 'jwt', {
    key: ACCESS_TOKEN_SECRET,
    validate,
    verifyOptions: { algorithms: ['HS256'] },
    // headerKey / tokenType bisa disesuaikan; default 'authorization' dan 'Bearer'
  });

  // default apply auth ke semua route; untuk public route pakai options: { auth: false }
  server.auth.default('jwt');

  // ROUTES

  // Public: login (demo: hanya username saja)
  server.route({
    method: 'POST',
    path: '/login',
    options: { auth: false },
    handler: async (request, h) => {
      const { username } = request.payload || {};
      // Demo: cari user berdasarkan username
      const user = Array.from(users.values()).find(u => u.username === username);
      if (!user) {
        return h.response({ error: 'Invalid credentials' }).code(401);
      }

      const accessToken = signAccessToken(user.id, { expiresIn: '15m' });
      const refreshToken = signRefreshToken(user.id, { expiresIn: '7d' });

      // simpan refresh token (rotasi/blacklist dipakai di produksi)
      refreshTokenStore.set(refreshToken, user.id);

      return { accessToken, refreshToken };
    }
  });

  // Public: refresh token endpoint (rotasi sederhana)
  server.route({
    method: 'POST',
    path: '/refresh',
    options: { auth: false },
    handler: async (request, h) => {
      const { refreshToken } = request.payload || {};
      if (!refreshToken) return h.response({ error: 'Refresh token required' }).code(400);
      const saved = refreshTokenStore.get(refreshToken);
      if (!saved) return h.response({ error: 'Invalid refresh token' }).code(401);

      try {
        const decoded = JWT.verify(refreshToken, REFRESH_TOKEN_SECRET);
        const userId = decoded.sub;

        // rotate: hapus old refresh token dan buat baru
        refreshTokenStore.delete(refreshToken);
        const newRefreshToken = signRefreshToken(userId, { expiresIn: '7d' });
        refreshTokenStore.set(newRefreshToken, userId);

        const newAccessToken = signAccessToken(userId, { expiresIn: '15m' });

        return { accessToken: newAccessToken, refreshToken: newRefreshToken };
      } catch (err) {
        return h.response({ error: 'Invalid or expired refresh token' }).code(401);
      }
    }
  });

  // Protected route contoh
  server.route({
    method: 'GET',
    path: '/protected',
    handler: (request, h) => {
      // user yang di-attach oleh validate() tersedia di:
      const user = request.auth.credentials;
      return { message: `Halo ${user.username}`, user };
    }
  });

  // Optional logout (revoke refresh token)
  server.route({
    method: 'POST',
    path: '/logout',
    handler: (request, h) => {
      const { refreshToken } = request.payload || {};
      if (refreshToken && refreshTokenStore.has(refreshToken)) {
        refreshTokenStore.delete(refreshToken);
      }
      // akses token client bisa dihapus di client; di server kita revok refresh token
      return { ok: true };
    }
  });

  return server;
};

// jalankan jika file dieksekusi langsung
if (require.main === module) {
  (async () => {
    const server = await createServer();
    await server.start();
    console.log('Server running at:', server.info.uri);
  })().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { createServer, users, refreshTokenStore, signAccessToken, signRefreshToken, ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET };
