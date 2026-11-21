#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  echo "请用普通用户运行本脚本，不要使用 sudo。" >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/services/lan-chat"
UNIT_DIR="${HOME}/.config/systemd/user"
ENV_DIR="${HOME}/.config/lan-chat"

NODE_BIN="$(command -v node || true)"
if [[ -z "${NODE_BIN}" ]] || ! command -v npm >/dev/null 2>&1; then
  echo "缺少 Node.js 或 npm。请先按 docs/部署.md 安装 Node.js 20 或更高版本。" >&2
  exit 1
fi

NODE_MAJOR="$("${NODE_BIN}" -p 'Number(process.versions.node.split(".")[0])')"
if [[ "${NODE_MAJOR}" -lt 20 ]]; then
  echo "Node.js 版本过低：$("${NODE_BIN}" --version)，需要 20 或更高版本。" >&2
  exit 1
fi

for required in package.json package-lock.json server.js device-access.js README.md deploy/lan-chat.service deploy/mcp-https-proxy.mjs; do
  if [[ ! -f "${SOURCE_DIR}/${required}" ]]; then
    echo "缺少 ${required}。请在完整的源码目录中运行本脚本。" >&2
    exit 1
  fi
done

install -d -m 700 "${APP_DIR}" "${APP_DIR}/public" "${APP_DIR}/test" "${APP_DIR}/deploy" "${APP_DIR}/data/uploads"
install -m 600 \
  "${SOURCE_DIR}/package.json" \
  "${SOURCE_DIR}/package-lock.json" \
  "${SOURCE_DIR}/server.js" \
  "${SOURCE_DIR}/device-access.js" \
  "${SOURCE_DIR}/README.md" \
  "${APP_DIR}/"
cp -R "${SOURCE_DIR}/public/." "${APP_DIR}/public/"
cp -R "${SOURCE_DIR}/test/." "${APP_DIR}/test/"
install -m 600 "${SOURCE_DIR}/deploy/mcp-https-proxy.mjs" "${APP_DIR}/deploy/mcp-https-proxy.mjs"

NODE_ESCAPED="$(printf '%s' "${NODE_BIN}" | sed 's/[\/&]/\\&/g')"
sed "s/\/usr\/bin\/node/${NODE_ESCAPED}/" "${SOURCE_DIR}/deploy/lan-chat.service" > "${APP_DIR}/deploy/lan-chat.service"
chmod 600 "${APP_DIR}/deploy/lan-chat.service"

cd "${APP_DIR}"
npm ci --omit=dev
npm test

install -d -m 700 "${UNIT_DIR}" "${ENV_DIR}"
if [[ ! -f "${ENV_DIR}/lan-chat.env" ]]; then
  install -m 600 "${SOURCE_DIR}/.env.example" "${ENV_DIR}/lan-chat.env"
fi
install -m 600 "${APP_DIR}/deploy/lan-chat.service" "${UNIT_DIR}/lan-chat.service"

if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "程序已安装到 ${APP_DIR}，自动测试已完成。" >&2
  echo "当前用户没有可用的 systemd 用户实例，因此没有启用开机服务。" >&2
  echo "可在该目录执行：PORT=9900 npm start" >&2
  exit 1
fi

systemctl --user daemon-reload
systemctl --user enable --now lan-chat.service

for _ in {1..30}; do
  if curl --fail --silent --show-error "http://127.0.0.1:9900/api/health" >/dev/null; then
    echo "邻聊已通过本机健康检查：http://127.0.0.1:9900/"
    echo "从其他设备访问时使用这台主机自己的地址。服务监听所有地址上的 9900 端口，请用防火墙限制来源。"
    echo "若未设置 ADMIN_PASSWORD，初始管理员密码在数据目录的 admin-password.txt，仅当前用户可读。不要提交或转发该文件。"
    exit 0
  fi
  sleep 1
done

echo "服务未在 30 秒内通过健康检查。可查看：journalctl --user -u lan-chat.service -n 100 --no-pager" >&2
exit 1
