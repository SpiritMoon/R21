include $(TOPDIR)/rules.mk

PKG_NAME:=cfm-control
PKG_VERSION:=2016.08.03

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

TARGET_LDFLAGS += $(if $(CONFIG_USE_EGLIBC),-lrt)

define Package/cfm-control
  SECTION:=utils
  CATEGORY:=hos-app
  TITLE:=for config files control
endef

define Package/cfm-control/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cluster-cfg $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/enc-plain $(1)/usr/bin/
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

$(eval $(call BuildPackage,cfm-control))
