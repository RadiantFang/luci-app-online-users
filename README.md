# luci-app-online-users

一个用于 LuCI 的在线设备页面插件，支持显示在线/离线设备、设备类型识别，以及对未知设备手动指定类型。

## 功能

- 在线设备统计：总设备、在线、离线
- 设备列表：状态、主机名、设备类型、IP、MAC、接口、租约剩余
- 后端数据来源：
  - DHCP 租约（自动读取 dnsmasq leasefile）
  - ARP / 邻居表（`/proc/net/arp` + `ip neigh`）
- 前端轮询刷新
- 未知设备可手动指定类型（按 MAC 保存到浏览器本地存储）

## 目录结构

- `luasrc/controller/online_users.lua`：后端接口与设备数据聚合
- `luasrc/view/online_users/index.htm`：LuCI 页面
- `root/usr/share/luci-online-users/oui.json`：厂商 OUI 数据文件（当前页面未展示厂商列）
- `po/zh_Hans/online_users.po`：中文翻译

## 在 ImmortalWrt / OpenWrt 编译树中使用

### 1. 放置源码

把本仓库放到编译树中的任一 package 目录，例如：

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

