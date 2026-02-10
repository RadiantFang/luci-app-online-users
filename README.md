# luci-app-online-users

一个用于 LuCI 的在线设备页面插件，展示在线/离线设备与基础网络信息。

## 功能

- 在线设备统计：总设备、在线、离线
- 设备列表：状态、主机名、IP、MAC、接口
- 多网卡主机合并：同 hostname 聚合显示，支持多个 IPv4
- 数据来源：
  - DHCP 租约（自动读取 dnsmasq leasefile）
  - ARP / 邻居表（`/proc/net/arp` + `ip neigh`）
  - IPv6 主机映射（odhcpd hosts）
- 前端轮询刷新（默认 5 秒）

## 说明

- 已移除厂商识别逻辑（不再依赖 OUI 数据库）
- 已移除“租约剩余”展示列

## 目录结构

- `luasrc/controller/online_users.lua`：后端接口与设备聚合逻辑
- `luasrc/view/online_users/index.htm`：LuCI 页面
- `po/zh_Hans/online_users.po`：中文翻译

## 在 ImmortalWrt / OpenWrt 编译树中使用

### 1. 拉取并放置源码

在编译树根目录执行（示例放到 `package/emortal`）：

```bash
cd <openwrt-root>
mkdir -p package/emortal
git clone https://github.com/RadiantFang/luci-app-online-users.git package/emortal/luci-app-online-users
```

或者使用 SSH：

```bash
git clone git@github.com:RadiantFang/luci-app-online-users.git package/emortal/luci-app-online-users
```

### 2. 更新并安装 feeds

```bash
cd <openwrt-root>
./scripts/feeds update -a
./scripts/feeds install -a
```

### 3. 选择插件

```bash
make menuconfig
```

路径一般在：

```text
LuCI -> Applications -> luci-app-online-users
```

### 4. 编译插件

```bash
make package/emortal/luci-app-online-users/compile V=s
```

### 5. 产物路径（示例）

```text
bin/packages/<arch>/<feed>/luci-app-online-users_1.1.0_all.ipk
bin/packages/<arch>/<feed>/luci-i18n-online-users-zh-cn_1.1.0-1_all.ipk
```

## 路由器安装

```bash
opkg install /tmp/luci-app-online-users_1.1.0_all.ipk
opkg install /tmp/luci-i18n-online-users-zh-cn_1.1.0-1_all.ipk
rm -f /tmp/luci-indexcache /tmp/luci-modulecache/*
/etc/init.d/uhttpd restart
```

打开 LuCI：

```text
状态 -> 在线用户
```
