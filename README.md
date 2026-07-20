# setup-proxy-action

自适应多协议（vless/vmess/trojan/hysteria2/tuic/anytls/socks5）代理节点解析 +
sing-box 启动，打包成 composite action，供其它 workflow / 其它仓库直接 `uses` 调用。

## 目录结构

```
setup-proxy-action/
├── action.yml
├── setup_proxy.py
└── README.md
```

把这三个文件提交到某个仓库（可以是你现有的自动化仓库，也可以单独建一个
`actions` 仓库），路径随意，比如 `owner/repo/.github/actions/setup-proxy`。

## 调用方式

同仓库调用（action 和 workflow 在同一个 repo）：

```yaml
jobs:
  renew:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup proxy
        id: proxy
        uses: alphaxcv/proxy_sb@1.0
        with:
          node_link: ${{ secrets.NODE_LINK }}

      - name: Use proxy
        run: |
          echo "is_proxy=${{ steps.proxy.outputs.is_proxy }}"
          echo "proxy_server=${{ steps.proxy.outputs.proxy_server }}"
          # 后续步骤里 IS_PROXY / PROXY_SERVER 也已写入 $GITHUB_ENV，
          # 可以直接当环境变量用
          echo "$IS_PROXY $PROXY_SERVER"
```

跨仓库调用（action 放在独立仓库，比如 `your-org/actions-lib`）：

```yaml
      - name: Setup proxy
        id: proxy
        uses: alphaxcv/proxy_sb@1.0
        with:
          node_link: ${{ secrets.NODE_LINK }}
```

`@main` 也可以换成具体的 tag（如 `@v1`）来锁版本，避免上游改动影响你的 workflow。

## 输入 (inputs)

| 参数 | 必填 | 说明 |
|---|---|---|
| `node_link` | 否 | 节点链接，如 `vless://uuid@host:port?...`。留空则跳过代理，直连模式 |
| `singbox_version` | 否 | 固定 sing-box 版本号（如 `1.13.14`）。不填则每次自动查询 GitHub Releases 最新稳定版 |

## 输出 (outputs)

| 输出 | 说明 |
|---|---|
| `is_proxy` | `'true'` / `'false'`，代理是否成功启动 |
| `proxy_server` | 代理地址，如 `socks5://127.0.0.1:1080`（仅 `is_proxy=true` 时有值） |

同时也会写入 `$GITHUB_ENV`（`IS_PROXY` / `PROXY_SERVER`），所以同一个 job 后续
的 shell 步骤既可以用 `steps.<id>.outputs.xxx`，也可以直接读环境变量。

## 限制

- 只支持 Linux runner（`ubuntu-latest` / 自建 Linux runner），sing-box 二进制
  按 `amd64/arm64/386/armv7/s390x` 架构自动选择。
- 代理监听在 `127.0.0.1:1080`（SOCKS5）和 `127.0.0.1:1081`（HTTP），固定端口，
  同一 job 内如果并行跑多个代理会冲突（正常场景一个 job 一个代理够用）。
- `node_link` 建议放在 repo/org secrets 里传入，不要明文写在 workflow 文件中。

## 建议的固定版本用法

避免每次 job 都打 GitHub API 请求（有速率限制风险），可以固定版本：

```yaml
      - uses: your-org/actions-lib/setup-proxy-action@main
        with:
          node_link: ${{ secrets.NODE_LINK }}
          singbox_version: '1.13.14'
```
