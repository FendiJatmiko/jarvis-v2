"""Curated list of common + historically-vulnerable WordPress plugin slugs.

Used by wp_fingerprint for active readme.txt probing so we enumerate the real
installed stack (including admin-only plugins) rather than only the handful we
have exploit recipes for. Not exhaustive — a pragmatic high-signal set biased
toward plugins that (a) are extremely common, or (b) have a history of
webshell-class vulns. Extend freely.
"""

COMMON_SLUGS = [
    # ubiquitous
    "contact-form-7", "akismet", "wordpress-seo", "elementor", "elementor-pro",
    "woocommerce", "jetpack", "wpforms-lite", "wordfence", "classic-editor",
    "all-in-one-seo-pack", "seo-by-rank-math", "wp-mail-smtp", "really-simple-ssl",
    "advanced-custom-fields", "mailchimp-for-wp", "tablepress", "redirection",
    "wordpress-importer", "duplicate-post",
    # caching / perf
    "litespeed-cache", "wp-super-cache", "w3-total-cache", "autoptimize", "wp-optimize",
    # page builders / themes stacks
    "colibri-page-builder", "colibri-page-builder-pro", "siteorigin-panels",
    "beaver-builder-lite-version", "wpbakery",
    # forms / uploads (webshell-adjacent surface)
    "ninja-forms", "formidable", "wpforms", "everest-forms",
    "wp-file-manager", "filester", "wp-file-upload", "simple-file-list",
    "drag-and-drop-multiple-file-upload-contact-form-7",
    # backup / migration (high-impact if abused)
    "updraftplus", "duplicator", "all-in-one-wp-migration",
    # comments / social
    "wpdiscuz", "disqus-comment-system",
    # misc high-install
    "wp-smushit", "wpml", "loginizer", "google-site-kit", "wp-google-maps",
    # premium autoblogging — not on wp.org, mass-exploited (CVE-2024-27956 SQLi)
    "wp-automatic",
]
