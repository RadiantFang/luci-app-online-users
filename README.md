# luci-app-online-users

一个用于 LuCI 的在线设备页面插件，展示在线/离线设备和基础网络信息。

## 功能

- 在线设备统计：总设备、在线、离线
- 设备列表：状态、主机名、IP、MAC、接口、租约剩余
- 后端数据来源：
  - DHCP 租约（自动读取 dnsmasq leasefile）
  - ARP / 邻居表（`/proc/net/arp` + `ip neigh`）
- 前端轮询刷新（默认 5 秒）

## 目录结构

- `luasrc/controller/online_users.lua`：后端接口与设备数据聚合
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

放置后的路径示例：

```bash
<openwrt-root>/package/emortal/luci-app-online-users
```

目录名建议保持为 `luci-app-online-users`。

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
make package/luci-app-online-users/compile V=s
```

如果你放在自定义目录（如 `package/emortal`），也可用：

```bash
make package/emortal/luci-app-online-users/compile V=s
```

### 5. 产物路径

编译完成后 ipk 一般在：

```text
bin/packages/<arch>/<feed>/luci-app-online-users_1_all.ipk
bin/packages/<arch>/<feed>/luci-i18n-online-users-zh-cn_unknown_all.ipk
```

## 路由器安装

```bash
opkg install luci-app-online-users_1_all.ipk
opkg install luci-i18n-online-users-zh-cn_unknown_all.ipk
/etc/init.d/uhttpd restart
```

打开 LuCI：

```text
状态 -> 在线用户
```
