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

## 启动 Web UI

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
