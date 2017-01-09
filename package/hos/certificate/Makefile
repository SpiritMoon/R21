include $(TOPDIR)/rules.mk


PKG_NAME:=certificate
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/certificate
  SECTION:=utils
  CATEGORY:=hos-app
  TITLE:=certificate programs
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			" 
endef

define Package/certificate/install
	install -d -m0700 $(1)/etc/cert
	install -m0400 $(PKG_BUILD_DIR)/CAhan.key $(1)/etc/cert/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/han-openssl.cnf $(1)/etc/cert/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mkca.sh $(1)/etc/cert/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/try_mkca.sh $(1)/etc/cert/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cert_ipmonitor $(1)/etc/cert/
	$(INSTALL_DIR) $(1)/etc/init.d
	install -m0700 $(PKG_BUILD_DIR)/certificate.init $(1)/etc/init.d/cert
endef

$(eval $(call BuildPackage,certificate))

