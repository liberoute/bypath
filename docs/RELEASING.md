# Publishing a stable release

The rolling `dev` release is not a stable release. Version tags trigger the
Build & Release workflow, which runs tests, lint, embedded-payload checks,
Docker integration and the 13-binary build matrix. It stages release assets
without publishing. Keep this manual approval boundary.

For v3.0.0, first verify the selected main commit and its green CI. Use an
authenticated GitHub CLI (`gh auth status`) and a clean, current clone:

```bash
git switch main
git pull --ff-only
git tag -a v3.0.0 -m "Bypath v3.0.0"
git push origin refs/tags/v3.0.0
```

Never move an existing release tag. Open the tag-triggered workflow in
[Actions](https://github.com/liberoute/bypath/actions), confirm the exact tag and commit and wait for
success. Download the `release-assets` artifact, not the rolling dev release.

On a Linux host or WSL, extract the artifact into a new directory and run:

```bash
sha256sum -c SHA256SUMS
bash -n install.sh
chmod +x bypath-full-linux-amd64 bypath-lite-linux-amd64
./bypath-full-linux-amd64 version
./bypath-lite-linux-amd64 version
```

Check that the reported version is v3.0.0 with the intended commit, the
variants are correct, and the archive contains all 13 binaries, install.sh,
THIRD_PARTY_NOTICES.md and SHA256SUMS (16 files total). The checksum file
must cover all 15 other assets. The version check assumes an amd64 Linux host.

Publish using GitHub's release editor or `gh release create`, selecting the
existing tag, uploading the 16 verified files, using the tagged
RELEASE_NOTES.md, leaving pre-release unchecked and marking it latest.
Do not reuse dev or RC binaries and do not overwrite existing releases.
After publishing, verify the public release and its exact tag.
