include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:= cluster_cor
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/cluster_cor
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:= cluster coordinate
   DEPENDS:=+libpthread
endef

define Package/cluster_cor/description
	Afi Config
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

define Package/cluster_cor/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cluster_cor $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tools/cluster_cli  $(1)/usr/bin/  
#	$(INSTALL_BIN) ./files/cluster_cli  $(1)/usr/bin/
	$(INSTALL_BIN) ./files/show_cluster  $(1)/usr/bin/
	
	
endef

$(eval $(call BuildPackage,cluster_cor))
