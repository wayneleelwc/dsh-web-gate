FROM node:22-alpine

# Zero-dependency gateway: only source is needed, no install step.
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY bin ./bin

ENV NODE_ENV=production
EXPOSE 3090

# State and config live in a volume so a password and signing secret survive
# container recreation. Mount a directory at /data.
VOLUME ["/data"]

ENTRYPOINT ["node", "bin/dsh-web-gate.js"]
CMD ["start", "--state", "/data/dsh-web-gate.state.json"]
