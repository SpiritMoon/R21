
include $(TOPDIR)/rules.mk

PKG_NAME:=libhccp
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/libhccp
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=libhccp
endef

define Package/libhccp/description
 This package contains hccp protocol library
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		all
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib $(1)/usr/include/libhccp
	$(CP) $(PKG_BUILD_DIR)/*.h $(1)/usr/include/libhccp
	$(CP) $(PKG_BUILD_DIR)/libhccp.a $(1)/usr/lib/
endef

define Package/libhccp/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libhccp.a $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libhccp))
