/**
 * Payload-variant expansion barrel (v0.20.0).
 *
 * Curated variant libraries + mechanical per-item expansion: the honest
 * answer to "tens of thousands of attacks" — real executions, counted
 * separately from intents, never inflated.
 */
export type { VariantClass, Variant, VariantPayload, VariantProgress, VariantCounts } from "./types.js";
export { VARIANT_CLASSES } from "./types.js";
export { SQLI_VARIANTS, XSS_VARIANTS, CMDI_VARIANTS, SSTI_VARIANTS, XXE_VARIANTS } from "./injection.js";
export { TRAVERSAL_VARIANTS, SSRF_VARIANTS, REDIRECT_VARIANTS } from "./traversal.js";
export { AUTH_VARIANTS } from "./auth.js";
export { HEADER_VARIANTS } from "./headers.js";
export { classifyItem, libraryForClass, totalLibrarySize, buildVariantsForClasses } from "./classify.js";
export {
  DEFAULT_VARIANT_CAP_STAGING,
  DEFAULT_VARIANT_CAP_PRODUCTION,
  resolveVariantCap,
  findBatteryItem,
  hasActiveVariantExpansion,
  startVariantExpansion,
  checkVariantCap,
  recordVariantExecution,
  closeVariantExpansion,
} from "./tracking.js";
export { countVariants, variantCountLine, variantProgressSuffix } from "./reporting.js";
export { VARIANT_LIST_TOOL } from "./tool.js";
