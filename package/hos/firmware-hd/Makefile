include $(TOPDIR)/rules.mk

PKG_NAME:=firmware-hd
PKG_VERSION:=2016.12.05

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/firmware-hd
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=Firmware Header Dump
   DEPENDS:=+libstdcpp
endef

define Package/firmware-hd/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/firmware-hd $(1)/sbin/
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CXX="$(TARGET_CXX)"
endef

$(eval $(call BuildPackage,firmware-hd))
