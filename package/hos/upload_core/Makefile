include $(TOPDIR)/rules.mk


PKG_NAME:=upload_core
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/upload_core
  SECTION:=utils
  CATEGORY:=hos-app
  TITLE:=upload_core upload core files to tftp server
endef

define Build/Compile

endef


define Package/upload_core/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./src/upload_core $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./src/upload_core_conf $(1)/etc/config/upload_core
endef

$(eval $(call BuildPackage,upload_core))

