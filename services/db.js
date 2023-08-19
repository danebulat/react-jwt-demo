import mysql from 'mysql2/promise';
import config from '../config.js';

/* execute a query and return results */
async function query(sql, params) {
  const connection  = await mysql.createConnection(config.db);
  const [results, ] = await connection.execute(sql, params);

  await connection.end();
  return results;
}

/* check for duplicate username */
async function isDuplicateUsername(username) {
  const sql = `SELECT COUNT(id) AS count FROM users WHERE username = '${username}'`;
  const result = await query(sql);
  return Number(result[0].count) === 0 ? false : true;
}

/* get total user count */
async function getUserCount() {
  const sql = 'SELECT COUNT(id) AS total FROM users';
  const result = await query(sql);
  return Number(result[0].total);
}

export {
  query,
  isDuplicateUsername,
  getUserCount,
};
