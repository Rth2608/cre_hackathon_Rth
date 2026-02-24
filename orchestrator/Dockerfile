FROM oven/bun:1.2

WORKDIR /app

COPY package.json ./
RUN bun install --production

COPY src ./src
COPY config ./config
COPY data ./data
COPY reports ./reports
COPY tsconfig.json ./tsconfig.json

ENV PORT=8787
EXPOSE 8787

CMD ["bun", "run", "src/server.ts"]
