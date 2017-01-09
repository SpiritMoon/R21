#!/bin/sh

TOPDIR=`pwd`
OPTION=""
SYSUPG=sysupgrade
AUTE_SYSUPG=autelan-sysupgrade
FILE_PATH=package/base-files/files/sbin
TAR_LIST=""

if [ $# -ge 1 ]; then
	OPTION=$1
fi

# multi compile jobs feature
jobs=1
if [ "$OPTION" = "-j" ]; then
	case "$2" in
    '' | *[!0-9]*)
        echo "invalid jobs number" >&2; exit 1;;
	esac

	if [ "$2" -gt "0" ]; then
		jobs=$2
	fi
fi

IMG_NAME=AFi-A1.img
DESC_FILE=image-describe
VERSION_NAME=openwrt-ar71xx-generic-ap152-afi-squashfs-sysupgrade.bin
FIRMWARE_NAME=openwrt-ar71xx-generic-afi-a1-squashfs-sysupgrade.bin
VERSION="`cat image-describe | awk -F " " '/version/ {print $3}'`"

rm -rf build_dir/target-*/hos-*
rm -rf build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/base-files
rm -rf tmp

prepare_hos_toolchain () {
    local ARCH
    local TOOLCHAIN_NAME="toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2"
    local TOOLCHAIN_BINARY
    local BINARY_PARENT="precompiled_binaries"

    if [ `file -L /sbin/init | awk '{print $3}'` = "64-bit" ]; then
        ARCH="x86_64"
    else
        ARCH="i386"
    fi

    TOOLCHAIN_BINARY=${BINARY_PARENT}/${ARCH}/${TOOLCHAIN_NAME}

    if [ ! -d staging_dir/$TOOLCHAIN_NAME ]; then
        echo "copying $TOOLCHAIN_BINARY"
        mkdir -p staging_dir
        cp $TOOLCHAIN_BINARY staging_dir/ -a
    fi


    sed 's/include toolchain\/Makefile/\#include toolchain\/Makefile/' Makefile > makefile
    echo "Note: makefile is generated from Makefile and will be overwritten, don't modifiy or commit it"
}

prepare_hos_toolchain


export AT_PRODUCT=AFI_A1
export AT_PLATFORM=AP152_AFI

rm -rf .config
cp AP152_AFI_A1.config .config
make defconfig

if [ $jobs -gt 1 ]; then
	echo "===== $jobs jobs compiling ====="
fi
make -j $jobs V=s

#cp $DESC_FILE bin/ar71xx/
cd bin/ar71xx/

rm -rf $DESC_FILE
touch $DESC_FILE

echo "config spec hardware" > $DESC_FILE && \
echo "	option hardtype		afi-a1" >> $DESC_FILE && \
echo "	option flashsize	16M"   >> $DESC_FILE && \
echo "	option flashcount	1" >> $DESC_FILE

#write spec sw info
echo "config spec software"         >> $DESC_FILE && \
echo "	option platform		newso"      >> $DESC_FILE

#get os type
echo "	option ha	single"             >> $DESC_FILE
echo "	option version	$VERSION"             >> $DESC_FILE
echo "	option md5	1"             >> $DESC_FILE

mv $VERSION_NAME $FIRMWARE_NAME

md5sum $FIRMWARE_NAME > sysupgrade.md5

TAR_LIST="$FIRMWARE_NAME $DESC_FILE sysupgrade.md5"
case $OPTION in
	-r)
	cp ../../$FILE_PATH/$AUTE_SYSUPG . 
	TAR_LIST="$TAR_LIST $AUTE_SYSUPG"
	;;
	-rr)
	cp ../../$FILE_PATH/$SYSUPG .
	TAR_LIST="$TAR_LIST $SYSUPG"
	;;
	-rrr)
	cp ../../$FILE_PATH/$AUTE_SYSUPG .
	cp ../../$FILE_PATH/$SYSUPG .
	TAR_LIST="$TAR_LIST $AUTE_SYSUPG $SYSUPG"
	;;
	*)
	;;
esac
tar zcvf $IMG_NAME $TAR_LIST

mv openwrt-ar71xx-generic-ap152-afi-kernel.bin	hos-r21-kernel.bin
mv openwrt-ar71xx-generic-ap152-afi-rootfs-squashfs.bin hos-r21-rootfs.bin
mv openwrt-ar71xx-generic-afi-a1-squashfs-sysupgrade.bin hos-r21-sysupgrade.bin

# generate upgrade bin file with header
SYSUPGRADE_BIN_NAME="hos-r21-sysupgrade.bin"
OSUPGRADE_BIN_NAME="hos-r21-osupgrade.bin"
$TOPDIR/staging_dir/host/bin/packbin "$TOPDIR" "afi-a1" $SYSUPGRADE_BIN_NAME $OSUPGRADE_BIN_NAME

cd ../..


