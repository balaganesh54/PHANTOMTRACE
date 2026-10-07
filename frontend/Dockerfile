FROM node:20-alpine
WORKDIR /app
COPY package.json tsconfig.json next-env.d.ts tailwind.config.ts postcss.config.js ./
RUN npm install
COPY app ./app
COPY components ./components
COPY lib ./lib
RUN npm run build
CMD ["npm","start"]
