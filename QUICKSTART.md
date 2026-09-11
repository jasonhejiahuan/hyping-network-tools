# QUICKSTART

## 安装依赖

```bash
source .venv-ft/bin/activate
python -m pip install -r requirements.txt
```

## 启动终端 UI

```bash
PYTHONPATH=src python -m hyping.main ui
```

如果已经安装为命令：

```bash
hyping ui
```

## 使用 root 启动

在 macOS 上，如果需要主动扫描整个网段，可使用 root 权限启动终端 UI：

```bash
sudo python3 -m hyping.main ui
```

从仓库根目录启动时可以省略 `PYTHONPATH`。也可以显式指定源码目录：

```bash
sudo PYTHONPATH=src python3 -m hyping.main ui
```

不使用 root 仍可运行 UI，并尝试 DNS、mDNS 和系统 ARP 缓存；主动 ARP 扫描可能因权限不足而跳过。

## 启动 Web UI

WebUI 默认启用 Passkey 验证。启动前请选择一种方式：

1. 下载并启动同作者的
   [jasonhejiahuan/Passkey-Auth](https://github.com/jasonhejiahuan/Passkey-Auth)。
   启动方法与 OAuth 参数配置请参考
   [Passkey-Auth Quick Start](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Quick-Start)
   和
   [Deployment](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Deployment)。
2. 如果暂时不需要登录门禁，在 `HypingData/hyping-config.json` 中设置：

   ```json
   {
     "web_auth": {
       "enabled": false
     }
   }
   ```

   也可以只为本次启动关闭：

   ```bash
   HYPING_WEB_AUTH_ENABLED=0 \
   PYTHONPATH=src python -m hyping.main web --port 8765
   ```

完成上述任一项后，再启动 WebUI：

```bash
PYTHONPATH=src python -m hyping.main web --port 8765
```

浏览器访问：

```text
http://localhost:8765
```

局域网其他设备访问时绑定到所有网卡：

```bash
PYTHONPATH=src python -m hyping.main web --host 0.0.0.0 --port 8765
```

然后访问：

```text
http://<本机 IP>:8765
```

完整的设备发现、WebUI Passkey 接入、配置与故障排查说明见
[项目 Wiki](https://github.com/jasonhejiahuan/hyping-network-tools/wiki)。
