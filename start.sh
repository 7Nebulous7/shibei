#!/bin/bash
# 启动 gunicorn（后台）
gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120 &
P1=$!

# 等待 gunicorn 就绪
sleep 3

# 下载 cloudflared client
if [ ! -f cloudflared ]; then
    curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
    chmod +x cloudflared
fi

# 启动 Cloudflare Tunnel，输出到日志
echo "====================================="
echo "  Cloudflare Tunnel starting..."
echo "  Your public URL will appear below:"
echo "====================================="
./cloudflared tunnel --url http://localhost:$PORT --no-autoupdate 2>&1

wait $P1
