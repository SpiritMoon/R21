include $(TOPDIR)/rules.mk

PKG_NAME:=configd
PKG_VERSION:=2016.07.17

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

TARGET_LDFLAGS += $(if $(CONFIG_USE_EGLIBC),-lrt)

define Package/configd
  SECTION:=utils
  CATEGORY:=hos-app
  TITLE:=for public configurations sync and reload
endef

define Package/configd/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/configd $(1)/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/configd.init $(1)/etc/init.d/configd
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

$(eval $(call BuildPackage,configd))
