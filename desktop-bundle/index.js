/**
 * @secscan/redteam-desktop-bundle - the SecScan red team as ONE profile bundle.
 *
 * The package's substance is `cordis.patch.yml`, declared by the
 * `dsh.bundle.patch` manifest field and resolved by the profile composer
 * through that field; this module carries no runtime API. (Same shape as
 * `@deepseek-ai/dsh-base`, which is the convention for bundle packages.)
 *
 * Why a bundle rather than loose patch entries: a profile composes as
 *   bundles in `dsh.profile.bundles` order -> the profile's own cordis.patch.yml
 *   -> launcher overlays
 * so shipping this as a bundle means the whole red team mounts from a single
 * name in that list. That is what makes it installable by a build (add the
 * name to PROFILE_TEMPLATES) and by a person (add the name to a profile's
 * package.json), with no hand-merged YAML either way.
 *
 * @module @secscan/redteam-desktop-bundle
 */

export {}
