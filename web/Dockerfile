FROM node:24-alpine AS development

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

EXPOSE 3000
CMD ["npm", "run", "dev"]

FROM development AS build
RUN npm run build

FROM nginx:1.29-alpine AS production
ENV NGINX_ENVSUBST_FILTER="^BANTAM_"
COPY --chmod=755 nginx-env.envsh /docker-entrypoint.d/15-bantam-proxy.envsh
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -q -O - http://127.0.0.1:3000/healthz || exit 1
