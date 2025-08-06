# ベースイメージ
FROM node:20

# 作業ディレクトリを作成
WORKDIR /app

# パッケージファイルだけ先にコピー
COPY package*.json ./

# パッケージインストール
RUN npm install

# 残りのファイルをコピー
COPY . .

# アプリを起動
CMD ["npm", "start"]
