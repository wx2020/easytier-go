include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-easytier
PKG_VERSION:=1.0.1
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for EasyTier Go
LUCI_DEPENDS:=+jq +curl
LUCI_PKGARCH:=aarch64_generic

define Package/$(PKG_NAME)/conffiles
/etc/config/easytier
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
