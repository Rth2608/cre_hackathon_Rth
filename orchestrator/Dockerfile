FROM oven/bun:1.2

WORKDIR /app

COPY package.json ./
RUN bun install --production

COPY src ./src
COPY scripts ./scripts
COPY config ./config
COPY data ./data
COPY reports ./reports
COPY tsconfig.json ./tsconfig.json
RUN chmod +x ./scripts/start_with_vector.sh

ENV PORT=8787
ENV VECTOR_SCREENING_PORT=9888
EXPOSE 8787

CMD ["bun", "run", "dev:with-vector"]
