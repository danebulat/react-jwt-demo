import 'dotenv/config';
import express from 'express';
import jwt     from 'jsonwebtoken';
import cors    from 'cors';
import bcrypt  from 'bcrypt';
import path    from 'path';

import config  from './config.js';
import * as db from './services/db.js';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();
const router = express.Router();

app.use(cors());
app.use(express.json());

/* ---------------------------------------- */
/* Helper functions                         */
/* ---------------------------------------- */

function generateAccessToken(user) {
  return jwt.sign(
    {id: user.id, isAdmin: user.is_admin}, 
    config.jwt.secretKey,
    { expiresIn: '10m' }
  );
};

function generateRefreshToken(user) {
  return jwt.sign(
    {id: user.id, isAdmin: user.is_admin}, 
    config.jwt.secretRefreshKey,
    { expiresIn: '1d' }
  );
};

function comparePassword(password, hashPassword) {
  return bcrypt.compareSync(password, hashPassword);
}

async function performLogin(username, password) {

  //fetch user
  const row = await db.query(`SELECT id, username, password, is_admin, created_at FROM users 
    WHERE username='${username}'`);

  if (row.length) {

    //compare passwords
    if (!comparePassword(password, row[0].password)) {
      return null;
    }

    //generate tokens
    const user = row[0];
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    //insert refresh token
    const result = await db.query(`
      INSERT INTO jwt_refresh_tokens (user_id, refresh_token) 
      VALUES (${user.id}, '${refreshToken}')`);

    if (!result.affectedRows) {
      return null;
    }

    //return user
    return {
      username:  user.username,
      isAdmin:   user.is_admin,
      createdAt: user.created_at,
      accessToken,
      refreshToken,
    };
  }
  else {
    return null;
  }
}

/* ---------------------------------------- */
/* Public directory                         */
/* ---------------------------------------- */

router.use(express.static(
  path.resolve(path.join(__dirname, `/${config.builddir}`)))
);

/* ---------------------------------------- */
/* Token verification middleware            */
/* ---------------------------------------- */

function verify(req, res, next) {

  //sets req.user if sent token authenticates.
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
    //token's payload returned if verification succeeds
    jwt.verify(token, config.jwt.secretKey, (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid");
      }

      req.user = user;
      next();
    });
  }
  else {
    res.status(401).json('You are not authenticated');
  }
};

/* ---------------------------------------- */
/* POST /api/refresh                        */
/* ---------------------------------------- */

router.post("/api/refresh", async (req, res) => {
  
  //get user refresh token
  const refreshToken = req.body.token;

  if (!refreshToken) 
    return res.status(401).json('You are not authenticated!');

  //check if refresh token is valid
  const row = await db.query(`
    SELECT * FROM jwt_refresh_tokens
    WHERE refresh_token='${refreshToken}'
  `);

  if (!row.length)
    return res.status(403).json('Refresh token is not valid!');
  
  //if everything is ok, create new access + refresh tokens and send to user
  jwt.verify(refreshToken, config.jwt.secretRefreshKey, async (err, user) => {
    err && console.log(err);

    try {
      //delete old refresh token
      await db.query(`
        DELETE FROM jwt_refresh_tokens 
        WHERE refresh_token='${refreshToken}'
      `);

      //generate new tokens
      const newAccessToken = generateAccessToken(user);
      const newRefreshToken = generateAccessToken(user);

      //persist new refresh token
      await db.query(`
        INSERT INTO jwt_refresh_tokens (user_id, refresh_token)
        VALUES (${user.id}, '${newRefreshToken}')
      `);
      
      //return new access and refresh tokens
      res.status(200).json({ 
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    }
    catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Error generating new refresh token' });
    }
  });
});

/* ---------------------------------------- */
/* POST /api/register                       */
/* ---------------------------------------- */

router.post('/api/register', async (req, res, next) => {
  const {username, password} = req.body;

  try {
    if (await db.getUserCount() >= 100)
      return res.status(500).json({ error: 'Too many users exist.' });

    if (await db.isDuplicateUsername(username)) 
      return res.status(409).json({ error: 'Username already exists.' });
    
    const hashPassword = bcrypt.hashSync(password, 10);

    const sql = `
      INSERT INTO users (username, password)
      VALUES ('${username}', '${hashPassword}')`;

    const result = await db.query(sql);
    if (!result.affectedRows) {
      throw new Error("Error adding user");
    }

    const user = await performLogin(username, password);
    if (user) {
      res.json(user);
    } else {
      res.status(500).json({ error: 'Registration error' });
    }
  }
  catch (err) {
    console.error(`Error while creating user ${err.message}`);
    next(err);
  }
});

/* ---------------------------------------- */
/* POST /api/login                          */
/* ---------------------------------------- */

router.post('/api/login', async (req, res, next) => {
  try {
    const {username, password} = req.body;
    const result = await performLogin(username, password);
    if (result) {
      res.json(result);
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } 
  catch (err) {
    console.error(err);
    next(err);
  }
});

/* ---------------------------------------- */
/* POST /api/logout                         */
/* ---------------------------------------- */

router.post('/api/logout', verify, async (req, res) => {

  //delete refresh token
  const refreshToken = req.body.token;
  const user = req.user;

  try {
    const result = await db.query(`
      DELETE FROM jwt_refresh_tokens 
      WHERE user_id=${user.id} AND 
            refresh_token='${refreshToken}'
      `);
    
    const message = result.affectedRows
      ? 'You logged out successfully'
      : 'Unable to log out';

    res.status(200).json({ msg: message });
  }
  catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Unable to log out' });
  }
});

/* ---------------------------------------- */
/* DELETE /api/users/:id                    */
/* ---------------------------------------- */

router.delete('/api/users/:userId', verify, async (req, res, next) => {
  if (Number(req.user.id) === Number(req.params.userId) || req.user.isAdmin) {

    try {
      const sql = `DELETE FROM users WHERE id = ${req.user.id}`;
      await db.query(sql);
      res.status(200).json('User has been deleted');
    }
    catch (err) {
      console.error(err);
      next(err);
    }
  }
  else {
    res.status(403).json('You are not allowed to delete this user');
  }
});

/* ---------------------------------------- */
/* GET /api/users                           */
/* ---------------------------------------- */

router.get('/api/users', async (_req, res, next) => {
  try {
    const sql = 'SELECT username, created_at FROM users';
    const rows = await db.query(sql);
    const data = rows === [] ? [] : rows;

    const users = data.map(user => {
      return {
        username: user.username,
        createdAt: user.created_at,
      }
    }); 

    res.status(200).json(users);
  }
  catch (err) {
    console.log(`Error while getting users ${err.message}`);
    next(err);
  }
});

/* ---------------------------------------- */
/* Pass router to subdir                    */
/* ---------------------------------------- */

app.use(config.subdir, router);

/* ---------------------------------------- */
/* Error handler middleware                 */
/* ---------------------------------------- */

app.use((err, _req, res, _next) => {
  const statusCode = err.statusCode || 500;
  console.error(err.message, err.stack);
  res.status(statusCode).json({ message: err.message });
});

/* -------------------------------------------------- */
/* Catch-all route to index.html                      */
/* -------------------------------------------------- */

router.get('/*', (_req, res) => {
  res.sendFile(path.resolve(__dirname + `/${config.builddir}/index.html`));
});

/* ---------------------------------------- */
/* Listen                                   */
/* ---------------------------------------- */

console.log('builddir: ' + path.join(__dirname, `/${config.builddir}`));
console.log(`subdir: ${config.subdir}`);

app.listen(config.port, () => {
  console.log(`Server listening on port ${config.port}`);
});
