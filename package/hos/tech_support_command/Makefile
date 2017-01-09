include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=tech_support_command
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/tech_support_command
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=Tech Support Command
endef

define Package/tech_support_command/description
	Tech Support Command
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

define Package/tech_support_command/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tech_support_command $(1)/sbin/
endef

$(eval $(call BuildPackage,tech_support_command))
