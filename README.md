# Automatically update kernel versions

Automate update of sources required to build kernel in PKGBUILD and push it to OBS (Open Build Service) to build.

Updates the following:
- latest kernel stable based on daily cron
- clearlinux tag (as long as the major version still matches current kernel stable)
- cachyos patch names (more so the prefix numbers)
- b2sums of the sources using this [Arch Linux PKGBUILD Package action](https://github.com/marketplace/actions/arch-linux-pkgbuild-package)

Then pushes from /processed the updated PKGBUILD to an Open Build Service repository (as defined in obs.yml).
