FROM node:24-alpine

RUN corepack enable
WORKDIR /app

COPY ./package*.json ./

RUN --mount=id=npm,type=cache,target=/root/.npm,sharing=locked \
    npm install --omit=dev

COPY ./.env index.js ./
COPY ./views/ ./views/

USER node
EXPOSE 3000/tcp
CMD [ "npm", "start" ]
