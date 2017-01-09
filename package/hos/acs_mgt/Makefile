include $(TOPDIR)/rules.mk

PKG_NAME:= acs_mgt
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/acs_mgt
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:= acs_mgt
   DEPENDS:=+libhccp +libraries +libpthread
endef

define Package/acs_mgt/description
	acs mgt
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

CFLAGS+=-DPC018 -Wall -Wno-unused -g -O0 -I../auteos/src/include

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CC)" \
	CFLAGS="$(CFLAGS)"
endef

define Package/acs_mgt/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/acs_mgt $(1)/sbin/
endef

$(eval $(call BuildPackage,acs_mgt))
