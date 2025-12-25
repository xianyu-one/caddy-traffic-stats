FROM caddy:builder-alpine AS builder

# 1. 将当前目录（你的插件源码）复制到构建容器中的临时目录
# 注意：这需要你在项目根目录下执行 docker build
COPY . /workspace/caddy-traffic-stats

ENV GOPROXY=https://goproxy.cn,direct

# 2. 使用 xcaddy 编译
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/xianyu-one/caddy-traffic-stats=/workspace/caddy-traffic-stats && \
    apk update && \
    apk add upx wget && \
    upx -9 /usr/bin/caddy

WORKDIR /srv

# 下载默认配置作为保底（实际运行时通常会挂载你自己的 Caddyfile）
RUN wget -O /srv/Caddyfile https://raw.githubusercontent.com/caddyserver/dist/master/config/Caddyfile && \
    cp /usr/bin/caddy /srv/caddy

FROM scratch

ENV XDG_CONFIG_HOME /config
ENV XDG_DATA_HOME /data

WORKDIR /srv

COPY --from=builder /srv /srv

EXPOSE 80
EXPOSE 443
EXPOSE 443/udp
EXPOSE 2019

CMD ["/srv/caddy", "run", "--config", "/srv/Caddyfile", "--adapter", "caddyfile"]