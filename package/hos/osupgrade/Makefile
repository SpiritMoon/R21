include $(TOPDIR)/rules.mk

PKG_NAME:=osupgrade
PKG_VERSION:=2016.04.11

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/osupgrade
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=System Safely Upgrade
endef

define Package/osupgrade/description
	system safely upgrade
endef

define Package/osupgrade/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/osupgrade $(1)/sbin/
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CC)" 
endef

$(eval $(call BuildPackage,osupgrade))
