include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI app for online users
LUCI_DEPENDS:=+luci-base +luci-mod-status
LUCI_PKGARCH:=all

PKG_LICENSE:=GPL-3.0-only
PKG_MAINTAINER:=FmikGy
PKG_VERSION:=1.1.0
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)-$(PKG_RELEASE)

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
