include $(TOPDIR)/rules.mk

PKG_NAME:=core-mon
PKG_VERSION:=2016.08.15

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

TARGET_LDFLAGS += $(if $(CONFIG_USE_EGLIBC),-lrt)

define Package/core-mon
  SECTION:=utils
  CATEGORY:=hos-app
  TITLE:=key process guard
  DEPENDS:=+libpthread +librt
endef

define Package/core-mon/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/core-mon $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/
	$(INSTALL_BIN) ./files/core-mon.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/core-mon.init $(1)/etc/init.d/core-mon
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

$(eval $(call BuildPackage,core-mon))
