# {{BRAND_TITLE}} host shell — builds the {{HOST_NAME}} native-federation HOST
# (src -> dist/host-shell) and serves it via nginx with the strict nonce-CSP in
# nginx.conf. Angular CLI 22 requires Node >= 24.15.
FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build:host-shell

# nginx-unprivileged: runs as uid 101, binds 8080 (see nginx.conf) — no root in
# the serving container.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/host-shell/browser /usr/share/nginx/html
EXPOSE 8080
