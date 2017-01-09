# 
# Copyright (C) 2016-2026 han-networks.com
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=packbin

include $(INCLUDE_DIR)/host-build.mk

define Host/Compile
	$(HOSTCC) $(HOST_CFLAGS) $(HOST_STATIC_LINKING) -o $(HOST_BUILD_DIR)/packbin src/packbin.c
endef

define Host/Install
	$(CP) $(HOST_BUILD_DIR)/packbin $(STAGING_DIR_HOST)/bin/
endef

define Host/Clean
	rm -f $(STAGING_DIR_HOST)/bin/packbin
endef

$(eval $(call HostBuild))
