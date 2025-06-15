#!/bin/bash

# Requires latest_major
[ -z "$latest_major" ] && { echo '⚠️  latest_major is not set.'; exit 1; }

echo "🤖 Cachyos kernel patches update assistant 🤖"

# Set the repository and directory (latest_major)
repo="CachyOS/kernel-patches"
base_url="https://github.com/$repo/tree/master/$latest_major"

# Function to fetch patches
fetch_patches() {
  local url=$1
  local retries=5
  local delay=10
  local i
  local html_response

  for ((i=1; i<=retries; i++)); do
    # Fetch url
    html_response=$(curl -sL --retry 5 --retry-delay 10 --retry-max-time 60 "$url")

    # Return status by checking if html_response contains expected JSON tag
    if echo "$html_response" | grep -q 'data-target="react-app.embeddedData"'; then
      # Extract patch names
      patches_with_versions=$(echo "$html_response" | \
        grep -ozP '<script type="application/json" data-target="react-app.embeddedData">\K.*?(?=</script>)' | \
        tr -d '\0' | \
        sed 's/\\"/"/g; s/^[^{]*//; s/[^}]*$//' | \
        jq -r '.payload.tree.items[] | select(.name | endswith(".patch")) | .name' | sort | uniq)

      if [ -n "$patches_with_versions" ]; then
        echo "Fetched patches and their versions:"
        for patch in $patches_with_versions; do
          echo " - $patch"
        done
        return 0
      else
        echo "❌ No patch files found at $url. The directory may be empty or incorrectly formatted."
        return 1
      fi
    else
      echo "Attempt $i/$retries: Failed to fetch valid data from $url. Retrying in $delay seconds..."
      sleep $delay
      delay=$((delay * 2))
    fi
  done

  echo "❌ All retry attempts failed."
  return 1
}

# Try fetching from the base URL
if ! fetch_patches "$base_url"; then
  exit 1
fi

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