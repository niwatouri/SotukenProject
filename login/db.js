import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  host: 'db',
  user: 'postgres',
  password: 'postgres',
  database: 'mydb',
  port: 5432
});

export default pool;
