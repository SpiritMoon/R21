#
# Copyright (C) 2007-2014 OpenWrt.org
# Copyright (C) 2010 Vertical Communications
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=ztp
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

define Package/ztp
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=Zero Touch Provisioning 
   DEPENDS:=+libuci
endef

define Package/ztp/description
	Zero Touch Provisioning 
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile/Default

endef
Build/Compile = $(Build/Compile/Default)

define Package/ztp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/* $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ztp.init $(1)/etc/init.d/ztp
	install -d -m0700 $(1)/etc/cert
	$(INSTALL_BIN) ./files/cert/* $(1)/etc/cert
endef

$(eval $(call BuildPackage,ztp))
