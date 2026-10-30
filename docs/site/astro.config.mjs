// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The noqtis documentation site. NQSITE and NQBASE set where it is
// published (GitHub Pages by default: https://rootcoder007.github.io/noqtis);
// a custom domain sets NQBASE=/ and NQSITE to the domain.
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import links from "starlight-links-validator";

const site = process.env.NQSITE ?? "https://rootcoder007.github.io";
const base = process.env.NQBASE ?? "/noqtis";

export default defineConfig({
  site,
  base,
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "NOQTIS",
      logo: { src: "./src/assets/noqtis-hex.svg" },
      favicon: "/favicon.svg",
      description:
        "Post-quantum signatures and sealed, checkable records of the " +
        "exact files a result came from. C11, no dependencies.",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/rootcoder007/noqtis",
        },
      ],
      editLink: {
        baseUrl:
          "https://github.com/rootcoder007/noqtis/edit/main/docs/site/",
      },
      customCss: ["./src/styles/man.css"],
      lastUpdated: false,
      // NQPAGEFIND=0 skips the search index (Pagefind's binary does not run
      // on 16K-page arm64 kernels); CI always builds it
      pagefind: process.env.NQPAGEFIND !== "0",
      plugins: [links({ errorOnRelativeLinks: true })],
      sidebar: [
        {
          label: "Getting started",
          items: [
            { label: "Install", slug: "start/install" },
            { label: "Your first capsule", slug: "start/quick" },
            { label: "Check in your browser", slug: "demo" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Sign and verify a file", slug: "guides/sign" },
            { label: "Seal and check a capsule", slug: "guides/seal" },
            { label: "Check someone else's capsule", slug: "guides/others" },
            { label: "Keys and key files", slug: "guides/keys" },
            { label: "Timestamps", slug: "guides/timestamps" },
            { label: "Use in CI", slug: "guides/ci" },
            { label: "Recipes", slug: "recipes" },
          ],
        },
        {
          label: "Coming from",
          items: [
            { label: "sha256sum and GPG", slug: "from/sha256sum-gpg" },
            { label: "minisign or signify", slug: "from/minisign" },
            { label: "Sigstore", slug: "from/sigstore" },
            { label: "BagIt", slug: "from/bagit" },
          ],
        },
        {
          label: "Tutorials",
          items: [
            { label: "C library", slug: "guides/c" },
            { label: "Python", slug: "guides/py" },
            { label: "JavaScript", slug: "guides/js" },
            { label: "R", slug: "guides/r" },
          ],
        },
        {
          label: "Background",
          items: [
            { label: "Why post-quantum provenance now", slug: "explain/why" },
            { label: "How NOQTIS compares", slug: "explain/compare" },
          ],
        },
        {
          label: "Specification",
          items: [{ label: "Capsule format v1", slug: "spec/capsule" }],
        },
        {
          label: "Reference",
          items: [
            { label: "C API", slug: "reference/c-api" },
            { label: "Python API", slug: "reference/api/python" },
            { label: "JavaScript API", slug: "reference/api/javascript" },
            { label: "R API", slug: "reference/api/r" },
            { label: "Command line", slug: "reference/cli" },
            { label: "Exit codes and errors", slug: "reference/errors" },
            { label: "Glossary", slug: "glossary" },
            {
              label: "Manual pages",
              collapsed: true,
              items: [{ autogenerate: { directory: "reference/man" } }],
            },
          ],
        },
        { label: "Security", slug: "security" },
        { label: "Platforms", slug: "platforms" },
        { label: "FAQ", slug: "faq" },
      ],
    }),
  ],
});
