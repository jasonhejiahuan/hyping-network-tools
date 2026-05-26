# Hyping

A small terminal tool for finding devices on your local network.

Use it when you know a device is nearby, but you only remember part of its name,
its note, or you just want to see its IP and MAC address quickly.

## What it can do

- Find a device by hostname, for example `printer.local`.
- Find devices with partial names, for example `Ivan` or `MacBook-Air`.
- Show all matches instead of stopping at the first one.
- Save devices you care about with simple notes.
- Read Bonjour / mDNS details from devices that advertise them.
- Run a simple ping or TCP load test.
- Show your current network and subnet in the interactive UI.

## Quick start

This project currently targets Python 3.14 or newer.

From the project folder:

```bash
source .venv-ft/bin/activate
PYTHONPATH=src python -m hyping.main ui
```

If you install the package, you can use the shorter command:

```bash
hyping ui
```

## The easiest way to use it

Start the interactive UI:

```bash
PYTHONPATH=src python -m hyping.main ui
```

You will see a menu like this:

```text
1. 通过 hostname/note 查询 IP 和 MAC
2. 查询 mDNS/Bonjour 详细信息
3. 管理已保存设备
4. 并发 ping / TCP 负载测试
5. 退出
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

## Command examples

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
PYTHONPATH=src python -m hyping.main load 192.168.10.210 --protocol tcp --port 80
```

## About permissions

Some network actions work better with extra permission.

On macOS, active ARP scanning usually needs `sudo`:

```bash
sudo PYTHONPATH=src python -m hyping.main ui
```

Without `sudo`, Hyping still tries safer methods such as DNS, mDNS, and the
system ARP cache.

The UI only shows the elevated permission line when it is actually running with
that permission.

## About Wi-Fi names

Hyping tries to show the current network, interface, and subnet.

Example:

```text
当前网络：Wi-Fi | SSID: 未获取 | 接口: en0 | 网段: 192.168.8.0/22
```

On newer macOS versions, the Wi-Fi name may be hidden by the system and shown as
`SSID: 未获取`. That is normal. The subnet is still useful for finding devices.

## Saved devices

Saved devices are stored here by default:

```text
~/.hyping/devices.json
```

Use the UI menu `管理已保存设备` to view, select, or delete saved devices.

## Development

Run checks:

```bash
.venv-ft/bin/ruff check src tests
PYTHONPATH=src .venv-ft/bin/python -m unittest discover -s tests -q
.venv-ft/bin/python -m compileall -q src
```

## Notes

This is a personal network helper, not a full network management platform.
The goal is simple: find nearby devices quickly and keep the interface easy to
understand.
