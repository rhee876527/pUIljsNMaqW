# Caution! Please read what this package does before installing it on your machine!
#
# Maintainer: Anon ---> :-) 
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

# Only compile active modules to VASTLY reduce the number of modules built and
# the build time.
#
# To keep track of which modules are needed for your specific system/hardware,
# give module_db a try: https://aur.archlinux.org/packages/modprobed-db
# This PKGBUILD reads the database kept if it exists
#
# More at this wiki page ---> https://wiki.archlinux.org/index.php/Modprobed-db
_localmodcfg=

# Optionally select a sub architecture by number or leave blank which will
# require user interaction during the build. Note that the generic (default)
# option is 40.
#
#  1. AMD Opteron/Athlon64/Hammer/K8 (MK8)
#  2. AMD Opteron/Athlon64/Hammer/K8 with SSE3 (MK8SSE3)
#  3. AMD 61xx/7x50/PhenomX3/X4/II/K10 (MK10)
#  4. AMD Barcelona (MBARCELONA)
#  5. AMD Bobcat (MBOBCAT)
#  6. AMD Jaguar (MJAGUAR)
#  7. AMD Bulldozer (MBULLDOZER)
#  8. AMD Piledriver (MPILEDRIVER)
#  9. AMD Steamroller (MSTEAMROLLER)
#  10. AMD Excavator (MEXCAVATOR)
#  11. AMD Zen (MZEN)
#  12. AMD Zen 2 (MZEN2)
#  13. AMD Zen 3 (MZEN3)
#  14. AMD Zen 4 (MZEN4)
#  15. Intel P4 / older Netburst based Xeon (MPSC)
#  16. Intel Core 2 (MCORE2)
#  17. Intel Atom (MATOM)
#  18. Intel Nehalem (MNEHALEM)
#  19. Intel Westmere (MWESTMERE)
#  20. Intel Silvermont (MSILVERMONT)
#  21. Intel Goldmont (MGOLDMONT)
#  22. Intel Goldmont Plus (MGOLDMONTPLUS)
#  23. Intel Sandy Bridge (MSANDYBRIDGE)
#  24. Intel Ivy Bridge (MIVYBRIDGE)
#  25. Intel Haswell (MHASWELL)
#  26. Intel Broadwell (MBROADWELL)
#  27. Intel Skylake (MSKYLAKE)
#  28. Intel Skylake X (MSKYLAKEX)
#  29. Intel Cannon Lake (MCANNONLAKE)
#  30. Intel Ice Lake (MICELAKE)
#  31. Intel Cascade Lake (MCASCADELAKE)
#  32. Intel Cooper Lake (MCOOPERLAKE)
#  33. Intel Tiger Lake (MTIGERLAKE)
#  34. Intel Sapphire Rapids (MSAPPHIRERAPIDS)
#  35. Intel Rocket Lake (MROCKETLAKE)
#  36. Intel Alder Lake (MALDERLAKE)
#  37. Intel Raptor Lake (MRAPTORLAKE)
#  38. Intel Meteor Lake (MMETEORLAKE)
#  39. Intel Emerald Rapids (MEMERALDRAPIDS)
#  40. Generic-x86-64 (GENERIC_CPU)
#  41. Generic-x86-64-v2 (GENERIC_CPU2)
#  42. Generic-x86-64-v3 (GENERIC_CPU3)
#  43. Generic-x86-64-v4 (GENERIC_CPU4)
#  44. Intel-Native optimizations autodetected by the compiler (MNATIVE_INTEL)
#  45. AMD-Native optimizations autodetected by the compiler (MNATIVE_AMD)
_subarch=42

# Use the current kernel's .config file
# Enabling this option will use the .config of the RUNNING kernel rather than
# the ARCH defaults. Useful when the package gets updated and you already went
# through the trouble of customizing your config options.  NOT recommended when
# a new kernel is released, but again, convenient for package bumps.
_use_current=

# Enable compiling with LLVM
_use_llvm_lto=y

# Enable/Disable debug options
# Set 'y' to enable, 'n' to force disable debug options if already enabled in your
# .config file or leave empty to ignore debug options.
_debug=n

# Switch to stock build if needed
# useful for dot 0 releases or when clearlinux is out of sync... 
# This will invalidate all clear patches and build with stock kernel. 
# Note: Sources must be updated to reflect new build status
_switchstock=

#
##### below is where the magic happens
#
_major=6.11
_minor=4
_srcname=linux-${_major}
_clr=${_major}.3-1472
_gcc_more_v='20241001'
_cachy=CachyOS/kernel-patches/master
_lockdown=kelvie/917d456cb572325aae8e3bd94a9c1350/raw/74516829883c7ee7b2216938550d55ebcb7be609
_archlinuxpatch=aur.archlinux.org/cgit/aur.git/plain
pkgbase=linux-clear-llvm
pkgname=('linux-clear-llvm' 'linux-clear-llvm-headers')
pkgver=${_major}.${_minor}
pkgrel=1
pkgdesc='Clear Linux'
arch=('x86_64' 'x86_64_v2')
url="https://github.com/clearlinux-pkgs/linux"
license=(GPL-2.0-only)
makedepends=("bc" "cpio" "gettext" "git" "libelf" "pahole" "perl" "python" "tar" "xz" "zstd")

if [ -n "$_use_llvm_lto" ]; then
  makedepends+=(clang llvm lld)
fi

options=(!debug !strip)
if [ "$_debug" == "y" ]; then
    options=(!strip)
fi

source=(
  "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${_major}.tar.xz"
  "https://cdn.kernel.org/pub/linux/kernel/v6.x/patch-${pkgver}.xz"
  "https://github.com/clearlinux-pkgs/linux/archive/${_clr}.tar.gz"  
  "https://github.com/graysky2/kernel_compiler_patch/archive/$_gcc_more_v.tar.gz"
  "https://gist.githubusercontent.com/${_lockdown}/0001-Add-a-lockdown_hibernate-parameter.patch"
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0005-bbr3.patch"
#"https://raw.githubusercontent.com/${_cachy}/${_major}/misc/0001-le9uo.patch"
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0014-zstd.patch"  
  "https://raw.githubusercontent.com/${_cachy}/${_major}/0009-ksm.patch"
  "arch-0003-ASLR-bits.patch::https://${_archlinuxpatch}/0002-arch-Kconfig-Default-to-maximum-amount-of-ASLR-bits.patch?h=linux-llvm"
#"https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config"
  )

b2sums=(
            '0' #major
            '0' #minor-patches
            '0' #clear-patches
            '0' #cpu-arch-optimization
            '0' #lockdown 
            '0' #bbr3 
            '0' #le9uo
            '0' #zstd
            '0' #ksm
            '0' #max ASLR bits
            '0' #arch config
           )

# LLVM build option
if [ -n "$_use_llvm_lto" ]; then
  BUILD_FLAGS=(
    LLVM=1
    LLVM_IAS=1
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
        patch -Np1 -i ../patch-${pkgver}
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
            patch -Np1 -i "$srcdir/linux-${_clr}/${i}"
        done
    fi    
    
    ### Add all other patches
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
        echo "Setting config..."
        cp ../config .config
    else
        echo "Setting config..."
        cp -Tf $srcdir/linux-${_clr}/config ./.config
    fi

    ### Enable extra options
    echo "Enable extra options..."

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

    # Enable loadable module support
    scripts/config --undefine MODULE_SIG_FORCE \
                   --enable MODULE_COMPRESS_ZSTD

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

    # other extra misc improvements
   
    # enable PSI for oomd
    scripts/config --undefine CONFIG_PSI_DEFAULT_DISABLED
                  
    # BBRv3               
    scripts/config --module TCP_CONG_CUBIC \
                   --enable DEFAULT_BBR \
                   --disable DEFAULT_CUBIC \
                   --enable TCP_CONG_BBR \
                   --set-str DEFAULT_TCP_CONG bbr 
                   
    # enable basic upstream kernel hardening 
    make hardening.config

    # some overlooked configs good for security/performance
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

    make ${BUILD_FLAGS[*]} olddefconfig

    ### Checking config
    if [ -n "$_switchstock" ]; then
        diff -u ../config .config || :
    else
        diff -u $srcdir/linux-${_clr}/config .config || :
    fi

    # https://github.com/graysky2/kernel_compiler_patch
    # make sure to apply after olddefconfig to allow the next section
    echo "Patching to enable GCC optimization for other uarchs..."
    patch -Np1 -i "$srcdir/kernel_compiler_patch-$_gcc_more_v/more-ISA-levels-and-uarches-for-kernel-6.8-rc4+.patch"
    
    if [ -n "$_subarch" ]; then
        # user wants a subarch so apply choice defined above interactively via 'yes'
        yes "$_subarch" | make ${BUILD_FLAGS[*]} oldconfig
    else
        # no subarch defined so allow user to pick one
        make ${BUILD_FLAGS[*]} oldconfig
    fi

    ### Optionally use running kernel's config
    # code originally by nous; http://aur.archlinux.org/packages.php?ID=40191
    if [ -n "$_use_current" ]; then
        if [[ -s /proc/config.gz ]]; then
            echo "Extracting config from /proc/config.gz..."
            # modprobe configs
            zcat /proc/config.gz > ./.config
        else
            warning "Your kernel was not compiled with IKCONFIG_PROC!"
            warning "You cannot read the current config!"
            warning "Aborting!"
            exit
        fi
    fi

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
#	make ${BUILD_FLAGS[*]} -j${__nthreads} -C tools/bpf/bpftool vmlinux.h feature-clang-bpf-co-re=1 
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
