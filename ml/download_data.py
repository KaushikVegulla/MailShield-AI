"""Download the real public corpora used for training.

Sources (no account or API key needed):
- Phishing: Nazario Phishing Corpus, mbox files from monkey.org/~jose/phishing
- Legitimate: SpamAssassin public corpus, easy_ham and hard_ham archives

Files land in ml/data/ (git-ignored). Re-running skips existing files.
"""

from __future__ import annotations

import pathlib
import shutil
import time
import urllib.request

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"

# Every download is time-boxed: a corpus host that hangs must fail
# fast, never stall the caller. This matters most in the hosted
# build (ml/train_build.py), where an unbounded urlretrieve once
# left a Render build hanging on a slow personal server until the
# deploy died with it. Failures raise after the retries, and the
# build script turns that into a clean "no model this time" exit.
DOWNLOAD_TIMEOUT_SECONDS = 60
DOWNLOAD_ATTEMPTS = 2

FILES = {
    "phishing0.mbox": "https://monkey.org/~jose/phishing/phishing0.mbox",
    "phishing1.mbox": "https://monkey.org/~jose/phishing/phishing1.mbox",
    "phishing2.mbox": "https://monkey.org/~jose/phishing/phishing2.mbox",
    "phishing3.mbox": "https://monkey.org/~jose/phishing/phishing3.mbox",
    "easy_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
}


def download_file(url: str, dest: pathlib.Path) -> int:
    """Download one file with a hard timeout and retries.

    Streams to a .part file and renames on success, so a failed or
    interrupted attempt never leaves a truncated file that a later
    run would mistake for a complete download. Returns the size in
    bytes; raises the last error after DOWNLOAD_ATTEMPTS attempts.
    """
    part = dest.with_suffix(dest.suffix + ".part")
    last_error: Exception | None = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
                with open(part, "wb") as handle:
                    shutil.copyfileobj(response, handle, length=1024 * 256)
            part.replace(dest)
            return dest.stat().st_size
        except Exception as error:  # noqa: BLE001 - retried, then raised
            last_error = error
            print(f"  attempt {attempt} failed for {url}: {error}")
            part.unlink(missing_ok=True)
            if attempt < DOWNLOAD_ATTEMPTS:
                time.sleep(5)
    raise RuntimeError(f"could not download {url}") from last_error


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        dest = DATA_DIR / name
        if dest.exists() and dest.stat().st_size > 0:
            print(f"skip {name} (already downloaded, {dest.stat().st_size} bytes)")
            continue
        print(f"downloading {name} ...")
        size = download_file(url, dest)
        print(f"  -> {size} bytes")


if __name__ == "__main__":
    main()
