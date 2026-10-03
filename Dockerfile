FROM node:20-slim

WORKDIR /app

# No third-party runtime dependencies; only project files are needed.
COPY package.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts
COPY test ./test

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    AUDIT_FILE=/data/audits.json

RUN mkdir -p /data && npm run check

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
