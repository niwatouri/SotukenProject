# frontend/Dockerfile

# 1. ビルドステージ（viteを使っている前提）
FROM node:20 AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install

COPY . .
RUN npm run build 
 # viteの場合、dist フォルダに出力

# 2. 実行ステージ（Nginxで配信）
FROM nginx:stable-alpine

# ビルドされた静的ファイルをnginxが見るディレクトリへコピー
COPY --from=builder /app/dist /usr/share/nginx/html

# nginx設定ファイルを差し替え
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
