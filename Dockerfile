# Contributor control plane. Appliance release packaging is a later phase.
FROM node:22-bookworm-slim
WORKDIR /opt/kiln
COPY --chown=node:node . .
RUN npm ci
RUN chown -R node:node /opt/kiln/apps/dashboard
ENV NODE_ENV=development
USER node
EXPOSE 4000 3000
CMD ["node", "--import", "tsx", "apps/api/src/server.ts"]
