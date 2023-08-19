const devMode =
  Number(process.env.DEV_MODE) === 1;

const config = {

  /* database */
  db: {
    host:     process.env.MYSQL_HOST,
    user:     process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    port:     process.env.MYSQL_PORT,
    connectTimeout: 60_000,
    multipleStatements: true,
  },

  /* jwt */
  jwt: {
    secretKey:        process.env.JWT_SECRET_KEY,
    secretRefreshKey: process.env.JWT_SECRET_REFRESH_KEY,
  },

  /* express */
  port: devMode 
    ? process.env.PORT_DEV 
    : process.env.PORT_PROD,

  subdir: devMode 
    ? ''
    : process.env.SUBDIR,

  builddir: devMode 
    ? process.env.BUILD_DIR_DEV
    : process.env.BUILD_DIR_PROD,
};

export default config;
export { config };
