include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=rogueap
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/rogueap
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=RogueAP Identification
   DEPENDS:=+libuci +libpthread
endef

define Package/rogueap/description
	RogueAP Identification	
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

define Package/rogueap/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rogueap $(1)/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/rogueap.init $(1)/etc/init.d/rogueap
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/rogueap $(1)/etc/config/rogueap
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/rg_black $(1)/usr/sbin/rg_black
endef

$(eval $(call BuildPackage,rogueap))

