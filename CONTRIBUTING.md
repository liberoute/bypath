# Contributing to Bypath

Bug reports, documentation improvements, tests and focused pull requests are welcome.

## Before opening an issue

Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and existing issues. Include the
output of `bypath version`, the OS and architecture, build variant, operating
mode, expected behaviour and a minimal reproduction. If useful, include
redacted `sudo bypath doctor --json` output. Review diagnostics before posting:
remove credentials, tokens, subscription URLs and private infrastructure details.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than opening a
public issue.

## Development

Use Go 1.26 (the CI workflow pins the patch version). Fork the repository,
create a focused branch and run the following checks before submitting:

```sh
make lint
make test
make lite
```

Changes to embedded engines or network behaviour should also be checked against
the full build and Docker integration jobs in
[the CI workflow](.github/workflows/build.yml). For changes to proxy-guard
ownership, run `make test-guard` and `make test-guard-nonetadmin` in a disposable
Docker environment. Do not test firewall, DNS, gateway or service changes on a
production host.

Add regression tests for bug fixes, document configuration or behaviour changes,
and keep unrelated formatting or refactoring out of the same pull request.
Describe the changes, test results, limitations and any upgrade implications.
Never commit credentials, real proxy profiles or local build artifacts.

## License

Contributions are made under the project's [GPL-3.0-or-later license](LICENSE).
Preserve third-party notices and identify new dependencies and their licenses.
