#!/bin/bash

echo "🤖 Cachyos kernel patches update assistant 🤖"

# Fetch cachyos patch names and their versions
base_url="https://api.github.com/repos/CachyOS/kernel-patches/contents/$latest_major"
api_response=$(curl -sL "$base_url")
patches_with_versions=($(echo "$api_response" | grep -oP '"name": "\K[^"]*"' | grep -oP '^([0-9]{4})-([-\w]+)\.patch'))

# Path to PKGBUILD file
pkgbuild_file="PKGBUILD"
# Track update status
updates_made=false

if [ -f "$pkgbuild_file" ]; then
  # Fetch latest patch name versions
  echo "Fetched patches and their versions:"
  for patch in "${patches_with_versions[@]}"; do
    echo " - $patch"
  done

  # Loop through each patch name fetched from results
  for patch in "${patches_with_versions[@]}"; do
    current_version=$(echo "$patch" | awk -F'-' '{print $1}')
    patch_name=$(echo "$patch" | sed 's/^[0-9]\{4\}-//; s/\.patch$//')

    # Check for current versions in PKGBUILD
    current_in_pkgbuild=$(grep -oP "([0-9]{4})-([-\w]+)\.patch" "$pkgbuild_file" | grep -oP "([0-9]{4})-${patch_name}\.patch")

    # Print current version found in PKGBUILD
    if [ -n "$current_in_pkgbuild" ]; then
      echo "Current version in PKGBUILD for $patch_name: $current_in_pkgbuild"
    fi

    # Extract current version from PKGBUILD
    current_version_in_pkgbuild=$(echo "$current_in_pkgbuild" | grep -oP "^[0-9]{4}")

    # Compare current version to the new version
    if [ -n "$current_version_in_pkgbuild" ]; then
      if [ "$current_version_in_pkgbuild" != "$current_version" ]; then
        # Construct the old patch regex
        old_patch_regex="${current_version_in_pkgbuild}-${patch_name}.patch"

        # Construct the new patch URL using the new patch number
        new_patch_url="${current_version}-${patch_name}.patch"

        # Update the PKGBUILD file with the new constructed patch URL
        sed -i "s|$old_patch_regex|$new_patch_url|g" "$pkgbuild_file"
        echo "✅ Updated $old_patch_regex to $new_patch_url"
        updates_made=true
      else
        echo "⚠️ No update needed for $patch_name, version is already $current_version."
      fi
    fi
  done

  # Display feedback based on whether any updates were made
  if [ "$updates_made" = true ]; then
    echo "✅ Finished updating patch URLs in $pkgbuild_file"
  else
    echo "⚠️  No updates were necessary. PKGBUILD is already up-to-date!"
  fi
else
  echo "❌ Fatal error: An unexpected issue occurred. Check logs for more details."
  exit 1
fi
