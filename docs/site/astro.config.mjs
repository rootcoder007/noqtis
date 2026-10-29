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
            { label: "Command line", slug: "reference/cli" },
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
