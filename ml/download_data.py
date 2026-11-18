"""Download the real public corpora used for training.

Sources (no account or API key needed):
- Phishing: Nazario Phishing Corpus, mbox files from monkey.org/~jose/phishing
- Legitimate: SpamAssassin public corpus, easy_ham and hard_ham archives

Files land in ml/data/ (git-ignored). Re-running skips existing files.
"""

from __future__ import annotations

import pathlib
import urllib.request

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"

FILES = {
    "phishing0.mbox": "https://monkey.org/~jose/phishing/phishing0.mbox",
    "phishing1.mbox": "https://monkey.org/~jose/phishing/phishing1.mbox",
    "phishing2.mbox": "https://monkey.org/~jose/phishing/phishing2.mbox",
    "phishing3.mbox": "https://monkey.org/~jose/phishing/phishing3.mbox",
    "easy_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
}


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        dest = DATA_DIR / name
        if dest.exists() and dest.stat().st_size > 0:
            print(f"skip {name} (already downloaded, {dest.stat().st_size} bytes)")
            continue
        print(f"downloading {name} ...")
        urllib.request.urlretrieve(url, dest)
        print(f"  -> {dest.stat().st_size} bytes")


if __name__ == "__main__":
    main()
