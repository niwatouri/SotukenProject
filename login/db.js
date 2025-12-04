import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  host: 'postgres-db',
  user: 'postgres',
  password: '4hD@92kf!Qp7',
  database: 'mydb',
  port: 5432
});

export default pool;
