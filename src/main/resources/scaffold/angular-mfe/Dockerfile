# {{BRAND_TITLE}} {{TITLE_WORD}} — builds the {{APP_SLUG}} native-federation
# REMOTE (src -> dist/{{APP_SLUG}}) and serves it via nginx with CORS so the
# {{HOST_NAME}} host can fetch its remoteEntry.json cross-origin.
# Angular CLI 22 requires Node >= 24.15.
FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build:{{APP_SLUG}}

# nginx-unprivileged: runs as uid 101, binds 8080 (see nginx.conf) — no root in
# the serving container.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/{{APP_SLUG}}/browser /usr/share/nginx/html
EXPOSE 8080
