# Dahua POE Home Assistant Integration

<p align="center">
  <a href="https://github.com/slydiman/dahua_poe/releases"><img src="https://img.shields.io/github/v/release/slydiman/dahua_poe?display_name=tag&include_prereleases&sort=semver" alt="Current version" /></a>
  <img alt="GitHub" src="https://img.shields.io/github/license/slydiman/dahua_poe" />
  <img alt="GitHub manifest.json dynamic (path)" src="https://img.shields.io/github/manifest-json/requirements/slydiman/dahua_poe%2Fmain%2Fcustom_components%2Fdahua_poe?label=requirements" />
</p>

Unofficial integration for Home Assistant to local control [Dahua managed POE switches](https://transmission.dahuasecurity.com/en/product-list/Business/CloudManagementSolution).

Tested with DH-CS4010-8ET-110 and DH-CS4006-4ET-60.

# Installation

### Option 1: [HACS](https://hacs.xyz/) Link

1. Click [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=slydiman&repository=https%3A%2F%2Fgithub.com%2Fslydiman%2Fdahua_poe&category=Integration)
2. Restart Home Assistant

### Option 2: [HACS](https://hacs.xyz/)

1. Or `HACS` > `Integrations` > `⋮` > `Custom Repositories`
2. `Repository`: paste the url of this repo
3. `Category`: Integration
4. Click `Add`
5. Close `Custom Repositories` modal
6. Click `+ EXPLORE & DOWNLOAD REPOSITORIES`
7. Search for `dahua_poe`
8. Click `Download`
9. Restart _Home Assistant_

### Option 3: Manual copy

1. Copy the `dahua_poe` folder inside `custom_components` of this repo to `/config/custom_components` in your Home Assistant instance
2. Restart _Home Assistant_

# Configuration

This integration supports the local management only for now.
You need to know the IP address in the local network and the password.

[![Open your Home Assistant instance and show an integration.](https://my.home-assistant.io/badges/integration.svg)](https://my.home-assistant.io/redirect/integration/?domain=dahua_poe)

# Usage

This integration exposes power sensors and POE control switches. 
