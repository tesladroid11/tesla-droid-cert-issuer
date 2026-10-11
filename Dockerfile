FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && \
    npm cache clean --force && \
    chown -R node:node /app

COPY --chown=node:node src ./src
USER node

EXPOSE 8080
CMD ["npm", "start"]
