#-------------------------------------------------------------------------------
#
#
#-------------------------------------------------------------------------------
#
# makefile fragment that defines the build of the onie cross-compiled U-Boot
#

UBOOT_VERSION		= 2013.01.01
UBOOT_TARBALL		= u-boot-$(UBOOT_VERSION).tar.bz2
UBOOT_TARBALL_URLS	+= $(ONIE_MIRROR) ftp://ftp.denx.de/pub/u-boot
UBOOT_BUILD_DIR		= $(MBUILDDIR)/u-boot
UBOOT_DIR		= $(UBOOT_BUILD_DIR)/u-boot-$(UBOOT_VERSION)

UBOOT_SRCPATCHDIR	= $(PATCHDIR)/u-boot
UBOOT_PATCHDIR		= $(UBOOT_BUILD_DIR)/patch
UBOOT_DOWNLOAD_STAMP	= $(DOWNLOADDIR)/u-boot-download
UBOOT_SOURCE_STAMP	= $(STAMPDIR)/u-boot-source
UBOOT_PATCH_STAMP	= $(STAMPDIR)/u-boot-patch
UBOOT_BUILD_STAMP	= $(STAMPDIR)/u-boot-build
UBOOT_INSTALL_STAMP	= $(STAMPDIR)/u-boot-install
UBOOT_STAMP		= $(UBOOT_SOURCE_STAMP) \
			  $(UBOOT_PATCH_STAMP) \
			  $(UBOOT_BUILD_STAMP) \
			  $(UBOOT_INSTALL_STAMP)

UBOOT			= $(UBOOT_INSTALL_STAMP)

UBOOT_NAME		= $(shell echo $(MACHINE_PREFIX) | tr [:lower:] [:upper:])
UBOOT_MACHINE		?= $(UBOOT_NAME)
UBOOT_BIN		= $(UBOOT_BUILD_DIR)/$(UBOOT_MACHINE)/u-boot.bin
UBOOT_PBL		= $(UBOOT_BUILD_DIR)/$(UBOOT_MACHINE)/u-boot.pbl
UBOOT_INSTALL_IMAGE	= $(IMAGEDIR)/$(MACHINE_PREFIX).u-boot
UPDATER_UBOOT		= $(MBUILDDIR)/u-boot.bin
ifeq ($(UBOOT_PBL_ENABLE),yes)
  UPDATER_UBOOT		+= $(MBUILDDIR)/u-boot.pbl
  UPDATER_UBOOT_NAME	= u-boot.pbl
  UBOOT_IMAGE		= $(UBOOT_PBL)
else
  UPDATER_UBOOT_NAME	= u-boot.bin
  UBOOT_IMAGE		= $(UBOOT_BIN)
endif

UBOOT_IDENT_STRING	?= ONIE $(LSB_RELEASE_TAG)

PHONY += u-boot u-boot-download u-boot-source u-boot-patch u-boot-build \
	 u-boot-install u-boot-clean u-boot-download-clean

#-------------------------------------------------------------------------------

u-boot: $(UBOOT_STAMP)

DOWNLOAD += $(UBOOT_DOWNLOAD_STAMP)
u-boot-download: $(UBOOT_DOWNLOAD_STAMP)
$(UBOOT_DOWNLOAD_STAMP): $(PROJECT_STAMP)
	$(Q) rm -f $@ && eval $(PROFILE_STAMP)
	$(Q) echo "==== Getting upstream U-Boot ===="
	$(Q) $(SCRIPTDIR)/fetch-package $(DOWNLOADDIR) $(UPSTREAMDIR) \
		$(UBOOT_TARBALL) $(UBOOT_TARBALL_URLS)
	$(Q) touch $@

SOURCE += $(UBOOT_PATCH_STAMP)
u-boot-source: $(UBOOT_SOURCE_STAMP)
$(UBOOT_SOURCE_STAMP): $(TREE_STAMP) | $(UBOOT_DOWNLOAD_STAMP)
	$(Q) rm -f $@ && eval $(PROFILE_STAMP)
	$(Q) echo "==== Extracting upstream U-Boot ===="
	$(Q) $(SCRIPTDIR)/extract-package $(UBOOT_BUILD_DIR) $(DOWNLOADDIR)/$(UBOOT_TARBALL)
	$(Q) touch $@

#
# The u-boot patches are made up of a base set of platform independent
# patches with the current machine's platform dependent patches on
# top.
#
u-boot-patch: $(UBOOT_PATCH_STAMP)
$(UBOOT_PATCH_STAMP): $(UBOOT_SRCPATCHDIR)/* $(MACHINEDIR)/u-boot/* $(UBOOT_SOURCE_STAMP)
	$(Q) rm -f $@ && eval $(PROFILE_STAMP)
	$(Q) echo "==== Patching u-boot ===="
	$(Q) [ -r $(MACHINEDIR)/u-boot/series ] || \
		(echo "Unable to find machine dependent u-boot patch series: $(MACHINEDIR)/u-boot/series" && \
		exit 1)
	$(Q) mkdir -p $(UBOOT_PATCHDIR)
	$(Q) cp $(UBOOT_SRCPATCHDIR)/* $(UBOOT_PATCHDIR)
	$(Q) cat $(MACHINEDIR)/u-boot/series >> $(UBOOT_PATCHDIR)/series
	$(Q) $(SCRIPTDIR)/cp-machine-patches $(UBOOT_PATCHDIR) $(MACHINEDIR)/u-boot/series	\
		$(MACHINEDIR)/u-boot $(MACHINEROOT)/u-boot
	$(Q) $(SCRIPTDIR)/apply-patch-series $(UBOOT_PATCHDIR)/series $(UBOOT_DIR)
	$(Q) echo "#define ONIE_VERSION \
		\"onie_version=$(LSB_RELEASE_TAG)\\0\"	\
		\"onie_vendor_id=$(VENDOR_ID)\\0\"	\
		\"onie_platform=$(PLATFORM)\\0\"	\
		\"onie_machine=$(MACHINE)\\0\"		\
		\"platform=$(MACHINE)\\0\"		\
		\"onie_machine_rev=$(MACHINE_REV)\\0\"	\
		\"dhcp_vendor-class-identifier=$(PLATFORM)\\0\"	\
		\"dhcp_user-class=$(PLATFORM)_uboot\\0\"	\
		" > $(UBOOT_DIR)/include/configs/onie_version.h
	$(Q) echo '#define CONFIG_IDENT_STRING " - $(UBOOT_IDENT_STRING)"' \
		>> $(UBOOT_DIR)/include/configs/onie_version.h
	$(Q) echo '#define PLATFORM_STRING "$(PLATFORM)"' \
		>> $(UBOOT_DIR)/include/configs/onie_version.h
	$(Q) touch $@

ifndef MAKE_CLEAN
UBOOT_NEW = $(shell test -d $(UBOOT_DIR) && test -f $(UBOOT_BUILD_STAMP) && \
	       find -L $(UBOOT_DIR) -newer $(UBOOT_BUILD_STAMP) -print -quit)
endif

$(UBOOT_BUILD_DIR)/%/u-boot.bin: $(UBOOT_PATCH_STAMP) $(UBOOT_NEW) | $(XTOOLS_BUILD_STAMP)
	$(Q) echo "==== Building u-boot ($*) ===="
	$(Q) PATH='$(CROSSBIN):$(PATH)' $(MAKE) -C $(UBOOT_DIR)		\
		CROSS_COMPILE=$(CROSSPREFIX) O=$(UBOOT_BUILD_DIR)/$*	\
		$*_config
	$(Q) PATH='$(CROSSBIN):$(PATH)' $(MAKE) -C $(UBOOT_DIR)		\
		CROSS_COMPILE=$(CROSSPREFIX) O=$(UBOOT_BUILD_DIR)/$*	\
		all

$(UBOOT_BUILD_DIR)/%/u-boot.pbl: $(UBOOT_PATCH_STAMP) $(UBOOT_NEW) | $(XTOOLS_BUILD_STAMP)
	$(Q) echo "==== Building u-boot PBL image ($*) ===="
	$(Q) PATH='$(CROSSBIN):$(PATH)' $(MAKE) -C $(UBOOT_DIR)		\
		CROSS_COMPILE=$(CROSSPREFIX) O=$(UBOOT_BUILD_DIR)/$*	\
		$*_config
	$(Q) PATH='$(CROSSBIN):$(PATH)' $(MAKE) -C $(UBOOT_DIR)		\
		CROSS_COMPILE=$(CROSSPREFIX) O=$(UBOOT_BUILD_DIR)/$*	\
		$(UBOOT_PBL)

u-boot-build: $(UBOOT_BUILD_STAMP)
$(UBOOT_BUILD_STAMP): $(UBOOT_IMAGE)
	$(Q) rm -f $@ && eval $(PROFILE_STAMP)
	$(Q) touch $@

u-boot-install: $(UBOOT_INSTALL_STAMP)
$(UBOOT_INSTALL_STAMP): $(UBOOT_BUILD_STAMP)
	$(Q) echo "==== Installing u-boot ($(MACHINE_PREFIX)) ===="
	$(Q) cp -v $(UBOOT_IMAGE) $(UBOOT_INSTALL_IMAGE)
	$(Q) chmod a-x $(UBOOT_INSTALL_IMAGE)
	$(Q) ln -sf $(UBOOT_BIN) $(MBUILDDIR)/u-boot.bin
ifeq ($(UBOOT_PBL_ENABLE),yes)
	$(Q) ln -sf $(UBOOT_PBL) $(MBUILDDIR)/u-boot.pbl
endif
	$(Q) touch $@

CLEAN += u-boot-clean
u-boot-clean:
	$(Q) rm -rf $(UBOOT_BUILD_DIR)
	$(Q) rm -f $(UBOOT_STAMP)
	$(Q) rm -f $(IMAGEDIR)/*.u-boot
	$(Q) echo "=== Finished making $@ for $(PLATFORM)"

DOWNLOAD_CLEAN += u-boot-download-clean
u-boot-download-clean:
	$(Q) rm -f $(UBOOT_DOWNLOAD_STAMP) $(DOWNLOADDIR)/$(UBOOT_TARBALL)

#-------------------------------------------------------------------------------
#
# Local Variables:
# mode: makefile-gmake
# End:
