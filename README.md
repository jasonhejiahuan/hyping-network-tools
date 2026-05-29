# Hyping

[中文](#中文说明) | [English](#english)

## 中文说明

Hyping 是一个简单的终端网络工具，用来快速找到局域网里的设备。

当你只记得设备名字的一部分、备注，或者只想知道它的 IP 和 MAC 地址时，可以用它快速搜索。

### 它能做什么

- 通过 hostname 查找设备，例如 `printer.local`
- 通过部分名字查找设备，例如 `Ivan` 或 `MacBook-Air`
- 一次显示所有匹配设备，而不是只显示一个
- 列出当前网段下发现的所有设备
- 默认通过 Bettercap REST API 获取设备列表，速度更快
- 保存常用设备和备注
- 查看 Bonjour / mDNS 信息
- 做简单的 ping 或 TCP 负载测试
- 自定义测试负载大小
- 在交互界面显示当前网络和网段
- 用一个配置文件统一修改默认参数

### 快速开始

这个项目最低需要 Python 3.10；推荐使用 Python 3.14 或更新版本。

在项目目录运行：

```bash
source .venv-ft/bin/activate
PYTHONPATH=src python -m hyping.main ui
```

如果已经安装成命令，也可以直接运行：

```bash
hyping ui
```


### 首次启动指南

如果这是你第一次在这台电脑上运行 Hyping，建议按下面顺序来：

1. 确认 Python 版本。项目最低需要 Python 3.10；推荐使用 Python 3.14 或更新版本：

   ```bash
   python --version
   ```

2. 进入项目目录并安装依赖。如果你已经有 `.venv-ft`，可以直接激活它；否则先安装依赖：

   ```bash
   source .venv-ft/bin/activate
   python -m pip install -r requirements.txt
   ```

3. 启动交互界面：

   ```bash
   PYTHONPATH=src python -m hyping.main ui
   ```

4. 首次启动时，程序会自动创建默认配置文件：

   ```text
   ~/.hyping/config.json
   ```

   常用设备稍后保存到：

   ```text
   ~/.hyping/devices.json
   ```

5. 进入主界面后，先看顶部的当前网络信息，确认接口和网段是否正确。例如：

   ```text
   当前网络：Wi-Fi | SSID: SCBS-Student | 接口: en0 | 网段: 10.50.50.0/24
   ```

6. 第一次找设备，推荐先选择 `1. 通过 hostname/note 查询 IP 和 MAC`。如果你只想列出当前网段设备，可以选择 `2. 列出当前网段设备`。

如果扫描结果不完整，可能是权限或网络限制导致的。在 macOS 上，主动 ARP 扫描通常需要 `sudo`；默认 Bettercap 扫描则需要本机 Bettercap REST API 正在运行。

### 推荐使用方式

启动交互界面：

```bash
PYTHONPATH=src python -m hyping.main ui
```

你会看到这样的菜单：

```text
1. 通过 hostname/note 查询 IP 和 MAC
2. 列出当前网段设备
3. 查询 mDNS/Bonjour 详细信息
4. 管理已保存设备
5. 并发 ping / TCP 负载测试
6. 退出
```

选择 `1` 可以搜索设备。

可以输入完整名字：

```text
IvandeMacBook-Air.local
```

也可以只输入一部分：

```text
Ivan
```

如果找到多台设备，Hyping 会显示列表，让你继续选择：

```text
1. 选择一台作为当前设备
2. 保存一台设备
3. 保存全部设备
4. 查看一台设备详情
5. 返回
```

### 常用命令

通过 hostname 查找设备：

```bash
PYTHONPATH=src python -m hyping.main locate --hostname IvandeMacBook-Air.local
```

通过部分 hostname 查找设备：

```bash
PYTHONPATH=src python -m hyping.main locate --hostname Ivan --partial-hostname
```

打开交互界面：

```bash
PYTHONPATH=src python -m hyping.main ui
```

列出当前网段下的设备：

```bash
PYTHONPATH=src python -m hyping.main scan
```

默认会连接 Bettercap REST API：

```text
http://127.0.0.1:8081
用户名：user
密码：pass
```

扫描时会一边发现一边打印，不需要等全部扫描结束。Hyping 会直接使用 Bettercap 已经拿到的 hostname、vendor、mDNS 信息，不再自己慢慢解析。

### 修改默认配置

默认配置文件在：

```text
~/.hyping/config.json
```

第一次启动程序时，如果这个文件不存在，Hyping 会自动创建它。

想修改默认端口、Bettercap 地址、扫描时间、并发数等参数，直接改这个文件即可。命令行参数仍然可以临时覆盖配置文件里的默认值。

例如把 TCP 负载测试默认端口改成 `6000`：

```json
{
  "load": {
    "tcp_port": 6000
  }
}
```

你不需要写完整配置。缺少的项目会自动使用程序内置默认值。

如果要使用旧的内置 ARP 扫描器：

```bash
sudo PYTHONPATH=src python -m hyping.main scan --scanner builtin --network 192.168.8.0/22
```

如果网络比较大，或者 Wi-Fi 设备很多，可以增加扫描轮数：

```bash
sudo PYTHONPATH=src python -m hyping.main scan --scanner builtin --passes 5 --timeout 0.5
```

查看 mDNS / Bonjour 信息：

```bash
PYTHONPATH=src python -m hyping.main mdns-info --hostname IvandeMacBook-Air.local --merge
```

运行简单负载测试：

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --duration 10
```

使用 TCP 测试：

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --protocol tcp --port 5000
```

自定义每次发送的数据大小：

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --payload-size 1200
```

如果是你有权限测试的服务器，可以让 TCP 保持连接并持续发送数据：

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --protocol tcp --port 5000 --payload-size 65536 --tcp-keep-open
```

### 权限说明

有些网络操作需要更高权限才更准确。

在 macOS 上，主动 ARP 扫描通常需要 `sudo`：

```bash
sudo PYTHONPATH=src python -m hyping.main ui
```

不使用 `sudo` 也可以运行。Hyping 仍会尝试 DNS、mDNS 和系统 ARP 缓存。

如果程序真的在提升权限下运行，主界面会显示对应提示；否则不会显示。

### 关于 Wi-Fi 名称

Hyping 会尝试显示当前网络、接口和网段。

例如：

```text
当前网络：Wi-Fi | SSID: 未获取 | 接口: en0 | 网段: 192.168.8.0/22
```

在较新的 macOS 上，Wi-Fi 名称可能会被系统隐藏，所以看到 `SSID: 未获取` 是正常的。网段仍然可以用来查找设备。

### 保存的设备在哪里

默认保存到：

```text
~/.hyping/devices.json
```

在交互界面里选择 `管理已保存设备`，可以查看、选择或删除保存的设备。

### 开发检查

```bash
.venv-ft/bin/ruff check src tests
PYTHONPATH=src .venv-ft/bin/python -m unittest discover -s tests -q
.venv-ft/bin/python -m compileall -q src
```

### 说明

Hyping 不是复杂的大型网络管理平台。

它的目标很简单：快速找到附近设备，并且尽量保持界面容易理解。

## English

Hyping is a small terminal tool for finding devices on your local network.

Use it when you know a device is nearby, but you only remember part of its name,
its note, or you just want to see its IP and MAC address quickly.

### What it can do

- Find a device by hostname, for example `printer.local`.
- Find devices with partial names, for example `Ivan` or `MacBook-Air`.
- Show all matches instead of stopping at the first one.
- List all devices discovered on the current subnet.
- Use the Bettercap REST API by default for faster device discovery.
- Save devices you care about with simple notes.
- Read Bonjour / mDNS details from devices that advertise them.
- Run a simple ping or TCP load test.
- Customize the payload size for load tests.
- Show your current network and subnet in the interactive UI.
- Change default options from one config file.

### Quick start

This project requires Python 3.10 or newer; Python 3.14 or newer is recommended.

From the project folder:

```bash
source .venv-ft/bin/activate
PYTHONPATH=src python -m hyping.main ui
```

If you install the package, you can use the shorter command:

```bash
hyping ui
```


### First launch guide

If this is your first time running Hyping on this machine, use this sequence:

1. Check Python. The project requires Python 3.10 or newer; Python 3.14 or newer is recommended:

   ```bash
   python --version
   ```

2. Enter the project folder and install dependencies. If `.venv-ft` already exists, activate it first; otherwise install the requirements in your environment:

   ```bash
   source .venv-ft/bin/activate
   python -m pip install -r requirements.txt
   ```

3. Start the interactive UI:

   ```bash
   PYTHONPATH=src python -m hyping.main ui
   ```

4. On first launch, Hyping creates the default config file automatically:

   ```text
   ~/.hyping/config.json
   ```

   Saved devices are written later to:

   ```text
   ~/.hyping/devices.json
   ```

5. In the main screen, first check the current network line and make sure the interface and subnet look right. Example:

   ```text
   当前网络：Wi-Fi | SSID: SCBS-Student | 接口: en0 | 网段: 10.50.50.0/24
   ```

6. For your first lookup, choose `1. 通过 hostname/note 查询 IP 和 MAC`. If you only want to list nearby devices on the current subnet, choose `2. 列出当前网段设备`.

If scan results are incomplete, permissions or network restrictions may be the reason. On macOS, active ARP scanning usually requires `sudo`; the default Bettercap scanner also requires a running local Bettercap REST API.

### The easiest way to use it

Start the interactive UI:

```bash
PYTHONPATH=src python -m hyping.main ui
```

You will see a menu like this:

```text
1. 通过 hostname/note 查询 IP 和 MAC
2. 列出当前网段设备
3. 查询 mDNS/Bonjour 详细信息
4. 管理已保存设备
5. 并发 ping / TCP 负载测试
6. 退出
```

Choose `1` to search for devices.

You can type a full name:

```text
IvandeMacBook-Air.local
```

Or just part of a name:

```text
Ivan
```

If more than one device matches, Hyping shows a list and lets you choose what to
do next:

```text
1. 选择一台作为当前设备
2. 保存一台设备
3. 保存全部设备
4. 查看一台设备详情
5. 返回
```

### Command examples

Find one device by hostname:

```bash
PYTHONPATH=src python -m hyping.main locate --hostname IvandeMacBook-Air.local
```

Find devices by partial hostname:

```bash
PYTHONPATH=src python -m hyping.main locate --hostname Ivan --partial-hostname
```

Search the current subnet from the interactive UI:

```bash
PYTHONPATH=src python -m hyping.main ui
```

List devices on the current subnet:

```bash
PYTHONPATH=src python -m hyping.main scan
```

By default, Hyping connects to the Bettercap REST API:

```text
http://127.0.0.1:8081
username: user
password: pass
```

The scan prints devices as they are found, so you do not have to wait for the
whole scan to finish before seeing results. Hyping uses the hostname, vendor and
mDNS information already collected by Bettercap.

### Default config

The config file is:

```text
~/.hyping/config.json
```

Hyping creates it automatically the first time it runs if it does not exist.

Edit this file to change default values such as the Bettercap API address, scan
duration, load-test concurrency, or TCP port. Command-line arguments can still
override the config for one run.

Example:

```json
{
  "load": {
    "tcp_port": 6000
  }
}
```

You do not need to include every option. Missing values use the built-in
defaults.

Use the older built-in ARP scanner:

```bash
sudo PYTHONPATH=src python -m hyping.main scan --scanner builtin --network 192.168.8.0/22
```

For larger networks or busy Wi-Fi networks, increase the number of passes:

```bash
sudo PYTHONPATH=src python -m hyping.main scan --scanner builtin --passes 5 --timeout 0.5
```

Read mDNS / Bonjour info:

```bash
PYTHONPATH=src python -m hyping.main mdns-info --hostname IvandeMacBook-Air.local --merge
```

Run a quick load test:

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --duration 10
```

Run a TCP test instead of ping:

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --protocol tcp --port 5000
```

Send a larger payload per probe:

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --payload-size 1200
```

For higher TCP bandwidth on a server you control, keep connections open and keep
sending data:

```bash
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --protocol tcp --port 5000 --payload-size 65536 --tcp-keep-open
```

### About permissions

Some network actions work better with extra permission.

On macOS, active ARP scanning usually needs `sudo`:

```bash
sudo PYTHONPATH=src python -m hyping.main ui
```

Without `sudo`, Hyping still tries safer methods such as DNS, mDNS, and the
system ARP cache.

The UI only shows the elevated permission line when it is actually running with
that permission.

### About Wi-Fi names

Hyping tries to show the current network, interface, and subnet.

Example:

```text
当前网络：Wi-Fi | SSID: 未获取 | 接口: en0 | 网段: 192.168.8.0/22
```

On newer macOS versions, the Wi-Fi name may be hidden by the system and shown as
`SSID: 未获取`. That is normal. The subnet is still useful for finding devices.

### Saved devices

Saved devices are stored here by default:

```text
~/.hyping/devices.json
```

Use the UI menu `管理已保存设备` to view, select, or delete saved devices.

### Development

Run checks:

```bash
.venv-ft/bin/ruff check src tests
PYTHONPATH=src .venv-ft/bin/python -m unittest discover -s tests -q
.venv-ft/bin/python -m compileall -q src
```

### Notes

This is a personal network helper, not a full network management platform.
The goal is simple: find nearby devices quickly and keep the interface easy to
understand.
