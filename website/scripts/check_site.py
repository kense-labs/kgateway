#!/usr/bin/env python3
"""Check the public landing page and generated benchmark datasets."""

import json
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "website"
DATASETS = {
    "performance-data.json",
    "performance-comparison.json",
    "ai-gateway-comparison.json",
}


class Links(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.hrefs = set()
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        if tag == "a":
            self.hrefs.add(dict(attributes).get("href"))


def main():
    source = (SITE / "index.html").read_text(encoding="utf-8")
    links = Links(source).hrefs
    for name in ("install.sh", "install.ps1"):
        if f"./{name}" not in links or not (ROOT / name).is_file():
            raise SystemExit(f"missing installer or installer link for {name}")
    if "<title>kgateway</title>" not in source or (SITE / "docs/index.html").exists():
        raise SystemExit("site does not match the kgateway landing page")
    for name in DATASETS:
        dataset = SITE / "assets" / name
        if dataset.is_file() and not isinstance(json.loads(dataset.read_text(encoding="utf-8")), dict):
            raise SystemExit(f"{dataset.name} must be a JSON object")
    print("kgateway landing page and generated datasets passed")


if __name__ == "__main__":
    main()
