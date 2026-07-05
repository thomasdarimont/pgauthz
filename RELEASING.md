# Releasing pgauthz

The release flow is three scripts plus manual gates; the tag is the point of
record and is **signed** (SSH signing) from v0.8.0 onward.

```bash
./scripts/pre-release.sh          # local preflight: Go build/vet (authzen,
                                  # authzctl, BFF), diagram + Helm-policy
                                  # freshness, full stack test run, CHANGELOG
./scripts/bump-version.sh X.Y.Z   # version refs + CHANGELOG roll
git commit -am "Bump version to X.Y.Z" && git push
./scripts/release.sh X.Y.Z --push # waits for CI green, creates + pushes the
                                  # SIGNED tag
```

## Tag signing (SSH)

One-time setup — pick the SSH key that is (or will be) registered on your
GitHub account:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/<your-key>.pub
```

For the **Verified** badge on GitHub, upload the same public key at
*Settings → SSH and GPG keys → New SSH key* and select key type
**"Signing Key"** (an authentication-only key does not verify signatures,
even if it is the same key pair — add it a second time as a signing key).

`release.sh` refuses to create an unsigned tag: if signing is not
configured it prints these setup steps and aborts.

## Verifying a release tag

GitHub shows **Verified** on the tag when the signer's key is registered as
a signing key. To verify locally, git needs an *allowed signers* file
mapping identities to keys:

```bash
mkdir -p ~/.config/git
echo "release@pgauthz $(cat path/to/maintainer-key.pub)" >> ~/.config/git/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
git tag -v vX.Y.Z
```

The maintainer's current signing key is published on GitHub:
`https://github.com/thomasdarimont.keys` lists authentication keys;
signing keys are visible via the API
(`gh api users/thomasdarimont/ssh_signing_keys`).

## Review gates

[`CODEOWNERS`](.github/CODEOWNERS) marks the security-sensitive paths
(engine roles/migrations, OPA policies, CI, deploy) — with branch
protection enabled, changes there require an owner's review. Roadmap
(supply-chain hardening): release workflow building images by digest with
SBOMs, and a pinned `values-release.yaml`.
