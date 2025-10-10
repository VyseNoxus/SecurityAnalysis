FROM node:20-alpine
WORKDIR /app
COPY package.json vite.config.js index.html ./
RUN npm install
COPY src ./src
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
