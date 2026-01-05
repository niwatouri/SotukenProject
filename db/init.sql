-- db/init.sql

-- （PostgreSQLイメージ起動時に自動的に mydb が作成されているので、ここでデータベースを作る必要はありません）

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
