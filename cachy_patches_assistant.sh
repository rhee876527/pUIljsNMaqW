#!/bin/bash

# Requires latest_major
[ -z "$latest_major" ] && { echo '⚠️  latest_major is not set.'; exit 1; }

echo "🤖 Cachyos kernel patches update assistant 🤖"

# Set the repository and directory (latest_major)
repo="CachyOS/kernel-patches"
base_url="https://github.com/$repo/tree/master/$latest_major"

# Fetch the HTML content of the directory and HTTP status code
response=$(curl -sL --retry 3 --retry-delay 5 --retry-max-time 30 -w "%{http_code}" "$base_url")
http_response="${response: -3}"  
html_response="${response%???}"  

# Check for valid HTTP response
if [ "$http_response" -ne 200 ]; then
  echo "❌ Failed to fetch data from $base_url. HTTP response code: $http_response."
  exit 1
fi

# Check if HTML response is empty
if [ -z "$html_response" ]; then
  echo "❌ Empty response received from $base_url. Please verify the URL or server status."
  exit 1
fi

# Extract patch names from the HTML response
patches_with_versions=$(echo "$html_response" | grep -oP '(?<=href="/'$repo'/blob/master/'"$latest_major"'/)[^"]+' | grep -oP '^[0-9]{4}-[^/]+\.patch' | sort | uniq)

# Check if patches were found
if [ -z "$patches_with_versions" ]; then
    echo "❌ No patch files found at $base_url. The directory may be empty or incorrectly formatted."
    exit 1
fi

# Fetched patches and their versions
echo "Fetched patches and their versions:"
for patch in $patches_with_versions; do
    echo " - $patch"
done

# Path to PKGBUILD file
pkgbuild_file="PKGBUILD"
# Track update status
updates_made=false

if [ -f "$pkgbuild_file" ]; then
  # Loop through each patch name fetched from results
  for patch in $patches_with_versions; do
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
    echo "
    
........................................................................
    
⚠️ No updates were necessary. PKGBUILD is already up-to-date!"
  fi
else
  echo "❌ Fatal error: File not found or something else went wrong. Exiting."
  exit 1
fi
