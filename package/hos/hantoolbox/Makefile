include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=hantoolbox
PKG_RELEASE:=1
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

define Package/hantoolbox
	SECTION:=utils
	CATEGORY:=hos-app
	TITLE:=hantoolbox -- han misc tools
endef

# define Package/hantoolbox/description
# 	Some DIY tools: to use C realize it is easier than shell.
# endef

define Package/cluster_mgt/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/hantoolbox/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hantoolbox $(1)/usr/bin/
endef

$(eval $(call BuildPackage,hantoolbox))
