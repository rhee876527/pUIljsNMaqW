# Maintainer: Martin Kibera <martin.kibera.n at gmail dot com>
# Contributor: Josip Ponjavic <josipponjavic at gmail dot com>
#
# Link to forked project >>>
# https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=linux-clear&id=e6ad9bba1bf1114dc40e0cae217fe0af1abb513d
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
# Useful for testing without clearlinux patches/kernel config...
_switchstock=

# Select x86-64 ISA level in compiler
# Check using: /lib/ld-linux-x86-64.so.2 --help | grep supported
# NOTE: Defaults to x86-64-v3 unless a level (1,2,3,4) is provided.
_isa=${_isa:-3}

# -march flag
_isa_flag="-march=x86-64-v${_isa}"

# Use llvm by default. Blank to use gcc
_use_llvm_lto=y

# Basic kernel self hardening
# https://github.com/torvalds/linux/blob/master/kernel/configs/hardening.config
_basic_harden=y

######################
##########
####
_major=6.18
_minor=4
_srcname=linux-${_major}
_cachy=CachyOS/kernel-patches/master
_lockdown=kelvie/917d456cb572325aae8e3bd94a9c1350/raw/74516829883c7ee7b2216938550d55ebcb7be609
pkgbase=linux-clear-llvm
pkgname=('linux-clear-llvm' 'linux-clear-llvm-headers')
pkgver=${_major}.${_minor}
pkgrel=2
pkgdesc='Clear Linux'
arch=('x86_64')
url="https://github.com/rhee876527/pUIljsNMaqW"
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
  "https://github.com/clearlinux-pkgs/linux/archive/6.15.7-1591.tar.gz"
  "https://gist.githubusercontent.com/${_lockdown}/0001-Add-a-lockdown_hibernate-parameter.patch"
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0004-bbr3.patch"
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0005-block.patch"
  "https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config"
  )

b2sums=('b94b7b9bf18aca0c3e50baf79b009a1448fc6cd9c3ee019f641cc247dcf53a4abef4274ee0608ad8cd4943af69854363a95d26e117ff23620bb07dccb158859f'
        '2a78cd052874eb01d38b8857e7647ea3f5904f8ec030b4c90f6b56262ee1974ee76de4359cc1748b9f0e97c5a330f9ac6dd9e3ad8623b96150b3292cb870e33b'
        '9cfb071f5f8228706dfee3c17409af3956c8db9b32a097a6d638eefadb58708e5f7779e9c5030f52ecfd2acfc2789d0fc57c10a10c4c37e8a79878a3990e8aea'
        '77f7769745dfd4d0db6e6729dca34f75fc08c5e6e2969ebd7ef968d18ed2044a89bff5f03d9dff9d451d71ad98cb5958188b910fe2a68e6ef5cccaa36cd693b2'
        'e8e213e72ca84652f9b43061ce384913633e3ae81f2f8bfaa0f5670a47bbdd796490c261ae6468b552b9b4078ab1244734d015ff24f43bb22c8007cbfe0c9451'
        '06d7e9dff65377ab21ce6c40be87a50ca7879cce10a9c326126c013f45a02fc38a7c01a57c51daaa320042d147c5a9a729426d798d8e815ce658e2afa96e51d9'
        '5820a813e0c3da331e4e98cf2825756fa8b3b2117c991c7c92b22b172a9763891d5c2371484defc167846c102dde26b3f7f7d42952e5b04097e03951515b5fc7')

# Initialize build variables
BUILD_FLAGS=()
KCFLAGS=""
KCPPFLAGS=""

# Enable LLVM and -O3 optimization
if [ -n "$_use_llvm_lto" ]; then
    BUILD_FLAGS+=("LLVM=1")
    KCFLAGS="-O3"
fi

# Add ISA flag to compiler flags
if [ -n "$_isa_flag" ]; then
    KCFLAGS="${KCFLAGS:+$KCFLAGS }$_isa_flag"
    KCPPFLAGS="${KCPPFLAGS:+$KCPPFLAGS }$_isa_flag"
fi

# Set build flags
[ -n "$KCFLAGS" ] && BUILD_FLAGS+=("KCFLAGS=$KCFLAGS")
[ -n "$KCPPFLAGS" ] && BUILD_FLAGS+=("KCPPFLAGS=$KCPPFLAGS")

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
        P=Patch
        skip_nums=(0109 0134 0148 0137 0132 0125 0118 0138 0147 0165 0173 0174)
        skip_re=$(printf "|^${P}%s" "${skip_nums[@]}")
        skip_re="^${skip_re:1}"

        for patch_file in $(grep "^$P" "$srcdir/linux-6.15.7-1591/linux.spec" | \
                            grep -Ev "$skip_re" | \
                            sed -n 's/.*: //p'); do
            [ -n "$_use_llvm_lto" ] && [ "$patch_file" = "0133-novector.patch" ] && continue
            echo "Applying patch $patch_file..."
            patch -Np1 -i "$srcdir/linux-6.15.7-1591/$patch_file" || true
        done
    fi

    ### Add the cherry-picked patches
    local src
        for src in "${source[@]}"; do
        src="${src%%::*}"
        src="${src##*/}"
        [[ $src = *.patch ]] || continue
        echo "Applying patch $src..."
        patch -Np1 < "../$src"
    done

    ### Setting config
    if [ -n "$_switchstock" ]; then
        echo "Using clean config source..."
        cp ../config .config
    else
        echo "Setting clr config and merging any new values from archlinux config..."
        cp -Tf "$srcdir/linux-6.15.7-1591/config" ./.config
        # Append unique values from clean config to clr config
        while IFS= read -r line; do
            key=$(echo "$line" | sed -nE 's/^(# )?(CONFIG_[A-Za-z0-9_]+).*/\2/p')
            if [ -n "$key" ] && ! grep -qE "^(# )?$key[= ]" .config; then
                echo "$line" >> .config
            fi
        done < ../config
    fi


    ### Extra configs for clearlinux
    if [ -z "$_switchstock" ]; then
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

        # enable PSI for oomd
        scripts/config --undefine CONFIG_PSI_DEFAULT_DISABLED

        # Make schedutil default gov
        scripts/config --undefine CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE \
                       --enable CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL

        # Add landlock lsm
        scripts/config --set-str LSM "landlock,yama,loadpin,safesetid,integrity"

        # Increase MMAP minimum address
        scripts/config --set-val CONFIG_DEFAULT_MMAP_MIN_ADDR 65536

        # Good for security
        scripts/config --enable CONFIG_SECURITY_LOCKDOWN_LSM \
                       --disable CONFIG_LEGACY_TIOCSTI \
                       --enable CONFIG_SECURITY_LANDLOCK \
                       --enable CONFIG_SECURITY_LOCKDOWN_LSM_EARLY

        # Disable some debug options
        scripts/config --undefine CONFIG_LATENCYTOP \
                       --disable CONFIG_DEBUG_LIST \
                       --disable CONFIG_DEBUG_SG \
                       --disable CONFIG_DEBUG_NOTIFIERS \
                       --disable CONFIG_KVM_WERROR
    fi

    ### Other extra misc improvements

    # Disable scheduler debugging
    scripts/config --disable CONFIG_SCHED_DEBUG

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

    # LLVM Clang
    if [ -n "$_use_llvm_lto" ]; then
        scripts/config --disable LTO_NONE \
                       --enable LTO \
                       --enable LTO_CLANG \
                       --enable ARCH_SUPPORTS_LTO_CLANG \
                       --enable ARCH_SUPPORTS_LTO_CLANG_THIN \
                       --enable HAS_LTO_CLANG \
                       --enable LTO_CLANG_THIN \
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

    # Enable basic upstream kernel hardening
    if [ -n "$_basic_harden" ]; then
        make "${BUILD_FLAGS[@]}" hardening.config
        # Disable kcfi
        scripts/config --disable CONFIG_CFI_CLANG
    else
        echo "Skipping hardening.config..."
    fi

    ## Keep KCFI disabled
    scripts/config --disable CONFIG_ARCH_SUPPORTS_CFI \
                   --disable CONFIG_CFI

    ### Checking config
    if [ -n "$_switchstock" ]; then
        diff -u ../config .config || :
    else
        diff -u $srcdir/linux-6.15.7-1591/config .config || :
    fi

    # Run olddefconfig
    make "${BUILD_FLAGS[@]}" olddefconfig

    ### Optionally load needed modules for the make localmodconfig
    # See https://aur.archlinux.org/packages/modprobed-db
    if [ -n "$_localmodcfg" ]; then
        if [ -e $HOME/.config/modprobed.db ]; then
            echo "Running Steven Rostedt's make localmodconfig now"
            make "${BUILD_FLAGS[@]}" LSMOD=$HOME/.config/modprobed.db localmodconfig
        else
            echo "No modprobed.db data found"
            exit
        fi
    fi

    make -s kernelrelease > version
    echo "Prepared $pkgbase version $(<version)"

    [[ -z "$_makenconfig" ]] || make "${BUILD_FLAGS[@]}" nconfig

    ### Save configuration for later reuse
    cp -Tf ./.config "${startdir}/config-${pkgver}-${pkgrel}${pkgbase#linux}"
}

build() {
    cd ${_srcname}
  	__nthreads=$(($(nproc) + 1))
	make "${BUILD_FLAGS[@]}" -j${__nthreads} all
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
    ZSTD_CLEVEL=19 make "${BUILD_FLAGS[@]}" INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 \
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
