# Caution! Please read what this package does before installing it on your machine!
#
# Maintainer: Yet another BTW anon
#
# Original works by: Josip Ponjavic
# (Source project) >>>
# https://aur.archlinux.org/packages/linux-clear
# https://build.opensuse.org/package/show/home:metakcahura:kernel/linux-clear-llvm
#
#######################################################################
#
#
### BUILD OPTIONS
# Set the next two variables to ANYTHING that is not null to enable them

# Tweak kernel options prior to a build via nconfig
_makenconfig=

# Localmodconfig. https://wiki.archlinux.org/index.php/Modprobed-db
_localmodcfg=

# Enable/Disable debug options
# Set 'y' to enable, 'n' to force disable debug options if already enabled in your
# .config file or leave empty to ignore debug options.
_debug=n

# Switch to stock build if needed
# Useful for dot 0 releases or when clearlinux is out of sync... 
# This will invalidate all clear patches and build with stock kernel. 
# Note: Sources must be updated to reflect new build status. 
# You need to enable config from arch in sources or set your own
_switchstock=

# Enable x86-64 compiler ISA level
# Check using: /lib/ld-linux-x86-64.so.2 --help | grep supported
# NOTE: Defaults to x86-64-v3 unless a level is provided.
_isa_level=${_isa_level-3}

# Use llvm by default. Blank to use gcc
_use_llvm_lto=y

# Basic kernel self hardening
# https://github.com/torvalds/linux/blob/master/kernel/configs/hardening.config
_basic_harden=y

#
##### below is where the magic happens
#
_major=6.12
_minor=6
_srcname=linux-${_major}
_clr=6.12.4-1518
_gcc_more_v='20241018'
_cachy=CachyOS/kernel-patches/master
_lockdown=kelvie/917d456cb572325aae8e3bd94a9c1350/raw/74516829883c7ee7b2216938550d55ebcb7be609
_archlinuxpatch=archlinux/linux/commit/d4237b86322adb5b208fe51fc3b77b234f2e965d
pkgbase=linux-clear-llvm
pkgname=('linux-clear-llvm' 'linux-clear-llvm-headers')
pkgver=${_major}.${_minor}
pkgrel=1
pkgdesc='Clear Linux'
arch=('x86_64')
url="https://github.com/clearlinux-pkgs/linux"
license=(GPL-2.0-only)
makedepends=(bc cpio gettext libelf pahole perl python tar xz zstd)

if [[ -n "$_use_llvm_lto" ]]; then
  makedepends+=(clang llvm lld)
fi

options=(!strip !debug)
if [[ "$_debug" == "y" ]]; then
  options=(!strip)
fi


source=(
  "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${_major}.tar.xz"
  "https://cdn.kernel.org/pub/linux/kernel/v6.x/patch-${pkgver}.xz"
  "https://github.com/clearlinux-pkgs/linux/archive/${_clr}.tar.gz"
  "https://github.com/graysky2/kernel_compiler_patch/archive/$_gcc_more_v.tar.gz"
  "https://gist.githubusercontent.com/${_lockdown}/0001-Add-a-lockdown_hibernate-parameter.patch"
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0004-bbr3.patch"
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0012-zstd.patch"
  "arch-0001-ASLR-bits.patch::https://github.com/${_archlinuxpatch}.patch"
  #"https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config"
  )

b2sums=('b2ec2fc69218cacabbbe49f78384a5d259ca581b717617c12b000b16f4a4c59ee348ea886b37147f5f70fb9a7a01c1e2c8f19021078f6b23f5bc62d1c48d5e5e'
        'd7a64fd9e2b40528a8c58c4941871e19c33f534d8d074fa112c1aa98be8b2624a320f222bae5d3d4f69d8bdb303393e107dfc108ad0265c2d8aa420cc3184e7e'
        '916ad7b14428f31f603129a35ff1940041317cb74ca3ae35d2abcd59da3a16a9acc4214947859cf5904447e99ce90c3e20a5f24d05b5b231e56652607ff29ee5'
        'f103018e7a081709e531a3548e13d7803c83f020507bbeb9642a459c79c2edfa9579d368ac2a58f8eca0fec9ab52895506cbb9f30a2e67dc8065f08986579d21'
        '77f7769745dfd4d0db6e6729dca34f75fc08c5e6e2969ebd7ef968d18ed2044a89bff5f03d9dff9d451d71ad98cb5958188b910fe2a68e6ef5cccaa36cd693b2'
        '60b682cc32f6770068999ce2f4a7731ae1f56a77a1aace35a94fa6fb50ea427763ba93298c186a2080841175e09aa448887f11879ffdccce8a9e8730f0c014de'
        '1215d3d6107d638698d14d6f45c204d66d646828575171903fbac181944e3057c7922f8de027a33f37f044e431f20b96c3888e37123ebc7738d5824dc52ed410'
        '384e181dd87010a77364dcd2810dfc4fa54689a38ec000d179f50c82f8cb564d1b05cc5e8f00e8e01de3b0153b7712ef30c5435821df15a07a2a8a7d2248c1d2')

# LLVM build option
if [ -n "$_use_llvm_lto" ]; then
  BUILD_FLAGS=(
    LLVM=1
    KCFLAGS="-O3"
  )
fi

export KBUILD_BUILD_HOST=archlinux
export KBUILD_BUILD_USER=$pkgbase
export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

prepare() {
    cd ${_srcname}
    
    ### Add upstream patches
    if [ $_minor -eq 0 ]; then
        echo "Skipping minor version patch for early 0 release"
    else
        echo "Add upstream patches"
        patch -Np1 -i ../patch-${pkgver} || true
    fi

    ### Setting version
    echo "Setting version..."
    echo "-$pkgrel" > localversion.10-pkgrel
    echo "${pkgbase#linux}" > localversion.20-pkgname
    
    ### Add Clearlinux patches
    if [ -z "$_switchstock" ]; then
        for i in $(grep '^Patch' ${srcdir}/linux-${_clr}/linux.spec |\
                     grep -Ev '^Patch0132|^Patch0109|^Patch0118|^Patch0138|^Patch0113|^Patch0139|^Patch0147' | sed -n 's/.*: //p'); do
            if [ -n "$_use_llvm_lto" ]; then
                if [ "${i}" == "0133-novector.patch" ]; then
                    continue
                fi
            fi
            echo "Applying patch ${i}..."
            patch -Np1 -i "$srcdir/linux-${_clr}/${i}" || true
        done
    fi    
    
    ### Add extra cherry-picked patches
    local src
        for src in "${source[@]}"; do
        src="${src%%::*}"
        src="${src##*/}"
        [[ $src = *.patch ]] || continue
        echo "Applying patch $src..."
        patch -Np1 < "../$src" || true
    done		    

    ### Setting config
    if [ -n "$_switchstock" ]; then
        echo "Using clean config source..."
        cp ../config .config
    else
        echo "Setting config..."
        cp -Tf $srcdir/linux-${_clr}/config ./.config
    fi

    # General setup
    scripts/config --set-str DEFAULT_HOSTNAME archlinux \
                   --enable IKCONFIG \
                   --enable IKCONFIG_PROC \
                   --undefine RT_GROUP_SCHED

    # Power management and ACPI options
    scripts/config --enable ACPI_REV_OVERRIDE_POSSIBLE \
                   --enable ACPI_TABLE_UPGRADE

    # General architecture-dependent options
    scripts/config --enable KPROBES

    # Networking support
    scripts/config --enable NETFILTER_INGRESS
    
    # Virtualization support
    scripts/config --enable KVM_SMM

    # Device Drivers
    scripts/config --enable FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER \
                   --enable DELL_SMBIOS_SMM \
                   --module PATA_JMICRON \
                   --enable-after SOUND SOUND_OSS_CORE \
                   --enable SND_OSSEMUL \
                   --module-after SND_OSSEMUL SND_MIXER_OSS \
                   --module-after SND_MIXER_OSS SND_PCM_OSS \
                   --enable-after SND_PCM_OSS SND_PCM_OSS_PLUGINS \
                   --module AGP --module-after AGP AGP_INTEL --module-after AGP_INTEL AGP_VIA

    # Kernel hacking -> Compile-time checks and compiler options -> Make section mismatch errors non-fatal
    scripts/config --enable SECTION_MISMATCH_WARN_ONLY

    # File systems
    scripts/config --module NTFS3_FS \
                   --enable NTFS3_LZX_XPRESS \
                   --enable NTFS3_FS_POSIX_ACL

    scripts/config --module SMB_SERVER \
                   --enable SMB_SERVER_SMBDIRECT \
                   --enable SMB_SERVER_CHECK_CAP_NET_ADMIN \
                   --enable SMB_SERVER_KERBEROS5

    # Security options
    scripts/config --enable SECURITY_SELINUX \
                   --enable SECURITY_SELINUX_BOOTPARAM \
                   --enable SECURITY_SMACK \
                   --enable SECURITY_SMACK_BRINGUP \
                   --enable SECURITY_SMACK_NETFILTER \
                   --enable SECURITY_SMACK_APPEND_SIGNALS \
                   --enable SECURITY_TOMOYO \
                   --enable SECURITY_APPARMOR \
                   --enable SECURITY_YAMA

    # Library routines
    scripts/config --keep-case --enable FONT_TER16x32

    ### Other extra misc improvements
   
    # enable PSI for oomd
    scripts/config --undefine CONFIG_PSI_DEFAULT_DISABLED
                  
    # BBRv3               
    scripts/config --module TCP_CONG_CUBIC \
                   --enable DEFAULT_BBR \
                   --disable DEFAULT_CUBIC \
                   --enable TCP_CONG_BBR \
                   --module NET_SCH_FQ_CODEL \
                   --enable NET_SCH_FQ \
                   --disable CONFIG_DEFAULT_FQ_CODEL \
                   --enable CONFIG_DEFAULT_FQ \
                   --set-str DEFAULT_TCP_CONG bbr
    
    # More configs good for security/performance
    scripts/config --enable CONFIG_SECURITY_LOCKDOWN_LSM \
                   --disable CONFIG_LEGACY_TIOCSTI \
                   --enable CONFIG_SECURITY_LANDLOCK \
                   --enable CONFIG_SECURITY_LOCKDOWN_LSM_EARLY \
                   --undefine CONFIG_LATENCYTOP \
                   --disable CONFIG_DEBUG_LIST \
                   --disable CONFIG_DEBUG_SG \
                   --disable CONFIG_DEBUG_NOTIFIERS \
                   --disable CONFIG_KVM_WERROR \
                   --disable CONFIG_SCHED_DEBUG \
                   --set-val CONFIG_DEFAULT_MMAP_MIN_ADDR 65536    

    # Enables Clang thinLTO & KCFI
    if [ -n "$_use_llvm_lto" ]; then
        scripts/config --disable LTO_NONE \
                       --enable LTO \
                       --enable LTO_CLANG \
                       --enable ARCH_SUPPORTS_LTO_CLANG \
                       --enable ARCH_SUPPORTS_LTO_CLANG_THIN \
                       --enable HAS_LTO_CLANG \
                       --enable LTO_CLANG_THIN \
                       --enable CONFIG_CFI_CLANG \
                       --enable ARCH_SUPPORTS_CFI_CLANG \
                       --enable CFI_CLANG \
                       --enable HAVE_GCC_PLUGINS
    fi

    # Removing unnecessary debugging
    if [ "$_debug" == "y" ]; then
        scripts/config --enable DEBUG_INFO \
                       --enable DEBUG_INFO_BTF \
                       --enable DEBUG_INFO_DWARF4 \
                       --enable PAHOLE_HAS_SPLIT_BTF \
                       --enable DEBUG_INFO_BTF_MODULES
    elif [ "$_debug" == "n" ]; then
        scripts/config --disable DEBUG_INFO \
                       --disable DEBUG_INFO_BTF \
                       --disable DEBUG_INFO_DWARF4 \
                       --disable PAHOLE_HAS_SPLIT_BTF \
                       --disable DEBUG_INFO_BTF_MODULES
    fi

    # Set ISA level
    if [ -n "$_isa_level" ]; then
        echo "Patching to enable x86-64 compiler ISA level..."
        patch -Np1 -i "$srcdir/kernel_compiler_patch-$_gcc_more_v/lite-more-x86-64-ISA-levels-for-kernel-6.8-rc4+.patch"
        scripts/config --enable CONFIG_GENERIC_CPU
        scripts/config --set-val CONFIG_X86_64_VERSION "$_isa_level"
    else
        echo "Skip ISA level patch"
    fi

    # Enable basic upstream kernel hardening 
    if [ -n "$_basic_harden" ]; then
        make hardening.config
    else
        echo "Skipping hardening.config..."
    fi

    ### Checking config
    if [ -n "$_switchstock" ]; then
        diff -u ../config .config || :
    else
        diff -u $srcdir/linux-${_clr}/config .config || :
    fi

    # Run olddefconfig
    make ${BUILD_FLAGS[*]} olddefconfig
    
    ### Optionally load needed modules for the make localmodconfig
    # See https://aur.archlinux.org/packages/modprobed-db
    if [ -n "$_localmodcfg" ]; then
        if [ -e $HOME/.config/modprobed.db ]; then
            echo "Running Steven Rostedt's make localmodconfig now"
            make ${BUILD_FLAGS[*]} LSMOD=$HOME/.config/modprobed.db localmodconfig
        else
            echo "No modprobed.db data found"
            exit
        fi
    fi
    
    make -s kernelrelease > version
    echo "Prepared $pkgbase version $(<version)"

    [[ -z "$_makenconfig" ]] || make ${BUILD_FLAGS[*]} nconfig

    ### Save configuration for later reuse
    cp -Tf ./.config "${startdir}/config-${pkgver}-${pkgrel}${pkgbase#linux}"
}

build() {
    cd ${_srcname}
  	__nthreads=$(($(nproc) + 1))
	make ${BUILD_FLAGS[*]} -j${__nthreads} all
#	make ${BUILD_FLAGS[*]} -C tools/bpf/bpftool vmlinux.h feature-clang-bpf-co-re=1 
}

package_linux-clear-llvm() {
    pkgdesc="The $pkgdesc kernel and modules"
    depends=('coreutils' 'kmod' 'initramfs')
    optdepends=('wireless-regdb: to set the correct wireless channels of your country'
                'linux-firmware: firmware images needed for some devices'
                'modprobed-db: Keeps track of EVERY kernel module that has ever been probed - useful for those of us who make localmodconfig')
    provides=(VIRTUALBOX-GUEST-MODULES WIREGUARD-MODULE KSMBD-MODULE)
    #install=linux.install # trips up action upgrade checksums

    cd $_srcname

    local modulesdir="$pkgdir/usr/lib/modules/$(<version)"

    echo "Installing boot image..."
    # systemd expects to find the kernel here to allow hibernation
    # https://github.com/systemd/systemd/commit/edda44605f06a41fb86b7ab8128dcf99161d2344
    install -Dm644 "$(make -s image_name)" "$modulesdir/vmlinuz"

    # Used by mkinitcpio to name the kernel
    echo "$pkgbase" | install -Dm644 /dev/stdin "$modulesdir/pkgbase"

    echo "Installing modules..."
    ZSTD_CLEVEL=19 make ${BUILD_FLAGS[*]} INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 \
        DEPMOD=/doesnt/exist modules_install  # Suppress depmod

    # remove build link
    rm "$modulesdir"/build
}

package_linux-clear-llvm-headers() {
    pkgdesc="Headers and scripts for building modules for the $pkgdesc kernel"
    depends=(pahole)

    cd ${_srcname}
    local builddir="$pkgdir/usr/lib/modules/$(<version)/build"

    echo "Installing build files..."
    install -Dt "$builddir" -m644 .config Makefile Module.symvers System.map \
        localversion.* version vmlinux
    install -Dt "$builddir/kernel" -m644 kernel/Makefile
    install -Dt "$builddir/arch/x86" -m644 arch/x86/Makefile
    cp -t "$builddir" -a scripts

    # required when STACK_VALIDATION is enabled
    install -Dt "$builddir/tools/objtool" tools/objtool/objtool

    # required when DEBUG_INFO_BTF_MODULES is enabled
    if [ -f tools/bpf/resolve_btfids/resolve_btfids ]; then
        install -Dt "$builddir/tools/bpf/resolve_btfids" tools/bpf/resolve_btfids/resolve_btfids
    fi

    echo "Installing headers..."
    cp -t "$builddir" -a include
    cp -t "$builddir/arch/x86" -a arch/x86/include
    install -Dt "$builddir/arch/x86/kernel" -m644 arch/x86/kernel/asm-offsets.s

    install -Dt "$builddir/drivers/md" -m644 drivers/md/*.h
    install -Dt "$builddir/net/mac80211" -m644 net/mac80211/*.h

    # https://bugs.archlinux.org/task/13146
    install -Dt "$builddir/drivers/media/i2c" -m644 drivers/media/i2c/msp3400-driver.h

    # https://bugs.archlinux.org/task/20402
    install -Dt "$builddir/drivers/media/usb/dvb-usb" -m644 drivers/media/usb/dvb-usb/*.h
    install -Dt "$builddir/drivers/media/dvb-frontends" -m644 drivers/media/dvb-frontends/*.h
    install -Dt "$builddir/drivers/media/tuners" -m644 drivers/media/tuners/*.h

    # https://bugs.archlinux.org/task/71392
    install -Dt "$builddir/drivers/iio/common/hid-sensors" -m644 drivers/iio/common/hid-sensors/*.h

    echo "Installing KConfig files..."
    find . -name 'Kconfig*' -exec install -Dm644 {} "$builddir/{}" \;
    
    echo "Removing unneeded architectures..."
    local arch
    for arch in "$builddir"/arch/*/; do
        [[ $arch = */x86/ ]] && continue
        echo "Removing $(basename "$arch")"
        rm -r "$arch"
    done

    echo "Removing documentation..."
    rm -r "$builddir/Documentation"

    echo "Removing broken symlinks..."
    find -L "$builddir" -type l -printf 'Removing %P\n' -delete

    echo "Removing loose objects..."
    find "$builddir" -type f -name '*.o' -printf 'Removing %P\n' -delete

    echo "Stripping build tools..."
    local file
    while read -rd '' file; do
        case "$(file -Sib "$file")" in
            application/x-sharedlib\;*)      # Libraries (.so)
                strip -v $STRIP_SHARED "$file" ;;
            application/x-archive\;*)        # Libraries (.a)
                strip -v $STRIP_STATIC "$file" ;;
            application/x-executable\;*)     # Binaries
                strip -v $STRIP_BINARIES "$file" ;;
            application/x-pie-executable\;*) # Relocatable binaries
                strip -v $STRIP_SHARED "$file" ;;
        esac
    done < <(find "$builddir" -type f -perm -u+x ! -name vmlinux -print0)

    echo "Stripping vmlinux..."
    strip -v $STRIP_STATIC "$builddir/vmlinux"

    echo "Adding symlink..."
    mkdir -p "$pkgdir/usr/src"
    ln -sr "$builddir" "$pkgdir/usr/src/$pkgbase"
}
