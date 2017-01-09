include $(TOPDIR)/rules.mk


PKG_NAME:=cluster_mgt
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/cluster_mgt

include $(INCLUDE_DIR)/package.mk


define Package/cluster_mgt
  SECTION:=utils
  CATEGORY:=hos-app
  TITLE:=cluster management module
  DEPENDS:=+libpthread
endef



define Package/cluster_mgt/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" 
	#	exit 1;
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
	
endef

define Package/cluster_mgt/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cluster_mgt $(1)/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/cluster.init $(1)/etc/init.d/cluster
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/cluster $(1)/etc/config/
endef

$(eval $(call BuildPackage,cluster_mgt))

