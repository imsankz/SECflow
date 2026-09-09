# Sponsor patches for SEOflow & BacklinkFlow

The GitHub token used in this sandbox (`arena-ai-coding-agent[bot]`) only has write
access to `imsankz/SECflow`, so these cross-repo changes could **not** be pushed or
merged from here (verified: push to both repos returns HTTP 403). Everything is
prepared as ready-to-apply patches instead.

> SECflow itself is fully done: PR #2 (landing page + template → `gh-pages`) and
> PR #3 (README + `.github/FUNDING.yml` → `main`) were **merged** on 2026-09-09.

## Status per repo

| Repo | Website (`gh-pages`) | README + `FUNDING.yml` (`main`) |
|---|---|---|
| **SECflow** | ✅ merged (PR #2) | ✅ merged (PR #3) — repo ♥ Sponsor button active |
| **SEOflow** | 📦 patch below (site has no sponsor section yet) | 📦 patch below |
| **BacklinkFlow** | ✅ already has full sponsor section upstream | 📦 patch below |

## Patches (each verified to apply cleanly against current upstream)

| Patch | Base | Files | Change |
|---|---|---|---|
| `SEOflow-gh-pages-site.patch` | `gh-pages` | `index.html`, `assets/flow-design.css` | "Keep SeoFlow free" sponsor section (❤️ GitHub Sponsors + ☕ Ko-fi cards) before footer, sponsor links in footer bar, card styles matching the site's v3 design tokens |
| `SEOflow-main-README-FUNDING.patch` | `main` | `README.md`, `.github/FUNDING.yml` | README support blurb lists GitHub Sponsors + Ko-fi; adds `FUNDING.yml` → enables repo ♥ Sponsor button |
| `backlinkflow-main-README-FUNDING.patch` | `main` | `README.md`, `.github/FUNDING.yml` | README ☕ Support section lists GitHub Sponsors + Ko-fi; adds `FUNDING.yml` |

## Apply

```bash
# 1) SeoFlow website
git clone https://github.com/imsankz/SEOflow.git && cd SEOflow
git fetch origin gh-pages
git checkout -b pr/sponsor-site origin/gh-pages
git am /path/to/SEOflow-gh-pages-site.patch
git push -u origin pr/sponsor-site

# 2) SeoFlow README + funding
git fetch origin main
git checkout -b pr/sponsor-readme origin/main
git am /path/to/SEOflow-main-README-FUNDING.patch
git push -u origin pr/sponsor-readme

# 3) BacklinkFlow README + funding
git clone https://github.com/imsankz/backlinkflow.git && cd backlinkflow
git checkout -b pr/sponsor-readme origin/main
git am /path/to/backlinkflow-main-README-FUNDING.patch
git push -u origin pr/sponsor-readme
```

Then open PRs (base `gh-pages` for the site patch, `main` for the README patches):

```bash
gh pr create --base gh-pages --head pr/sponsor-site --title "feat: add sponsor section (GitHub Sponsors + Ko-fi)"
gh pr create --base main --head pr/sponsor-readme --title "docs: add GitHub Sponsors to Support section + FUNDING.yml"
```

Alternatively `git apply <patch>` then commit yourself (`git apply` keeps the working
tree; `git am` also preserves the commit message).

> SEOflow has an existing open README PR (`docs/readme-seo-fixes`, #1) that edits the
> middle of `README.md` only — no overlap with the tail edit here.

## Reference links

- GitHub Sponsors profile: https://github.com/sponsors/imsankz (live)
- Ko-fi: https://ko-fi.com/chasingwhereabouts
- SECflow PR #2 (site): https://github.com/imsankz/SECflow/pull/2 — merged
- SECflow PR #3 (README + FUNDING): https://github.com/imsankz/SECflow/pull/3 — merged

## Cleanup

This folder lives on the `arena/01a082ce-secflow` branch of SECflow only so the
patches are downloadable (e.g. raw.githubusercontent.com). It is **not** part of the
published site's navigation — delete the folder once you've applied the patches.
