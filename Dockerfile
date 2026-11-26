FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
COPY web/package*.json ./web/
RUN npm ci && npm --prefix web ci
COPY tsconfig.json ./
COPY src ./src
COPY web ./web
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/web/dist ./web/dist
COPY package.json ./
EXPOSE 3000
CMD ["node", "dist/main.js"]
