# Contributing

Contributions are welcome. **Security problems do not go here**: see [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a fix, open an issue first and say what you want to change and why.
- By contributing you agree that your contribution is licensed under the licence in [LICENSE](LICENSE).
  There is no separate contributor agreement.
- Be decent: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Set up and run the checks

From a clone, Python 3.10 or later:

    python -m venv .venv
    # Windows PowerShell: .\.venv\Scripts\Activate.ps1   Linux/macOS: . .venv/bin/activate
    python -m pip install -e . pytest
    python -m pytest -q
    python spec/tools/make_vectors.py --check
    python scripts/check_install_lines.py
    ports/conformance/run.sh          # every engine whose toolchain you have
    ports/conformance/interop.sh      # every port's agent against the Python coordinator

## Rules a change must keep

1. No secrets, keys, tokens or personal data in the repository. Key files (`*.key`) are ignored by git;
   tests make fresh keys in temporary folders, and the vector generator uses test keys derived from
   public labels.
2. No new runtime dependency without a maintainer's decision (the Python package depends on
   `cryptography` only; every port has none).
3. A change to the protocol changes the vectors: run `python spec/tools/make_vectors.py`, review the diff
   of `spec/conformance/`, copy the files to `src/sf_smartswitch/data/conformance/`, and update every
   port until `ports/conformance/run.sh` and `interop.sh` pass. The vectors are the contract.
4. A change must keep the two promises (tests/test_protocol.py): one keyholder can neither trigger nor
   block a quorum action, and agents accept nothing they have not verified.
5. Say what was tested and what was not. Do not write that something works on a platform or at a scale
   it was not run on.
6. Install lines name only packages listed with `"registered": true` in `names.json`;
   `scripts/check_install_lines.py` enforces it in CI.
7. Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Pull requests

One topic per pull request. Describe what changes for a user, which tests cover it, and the commands
you ran with their results.
