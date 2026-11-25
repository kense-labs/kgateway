#!/usr/bin/env python3
"""Regenerate Formula/kgateway.rb with new version and sha256 values."""
import os
import sys

ver             = os.environ["VER"]
sha_macos_arm64 = os.environ["SHA_MACOS_ARM64"]
sha_macos_x64   = os.environ["SHA_MACOS_X64"]
sha_linux_arm64 = os.environ["SHA_LINUX_ARM64"]
sha_linux_x64   = os.environ["SHA_LINUX_X64"]

base = f"https://github.com/kense-labs/kgateway/releases/download/v{ver}"

formula = (
    'class Kgateway < Formula\n'
    '  desc "AI-native API gateway — SSE streaming, scale-to-zero, safe model rollouts"\n'
    '  homepage "https://github.com/kense-labs/kgateway"\n'
    f'  version "{ver}"\n'
    '  license "MIT"\n'
    '\n'
    '  on_macos do\n'
    '    on_arm do\n'
    f'      url "{base}/kgateway-{ver}-darwin-arm64.tar.gz"\n'
    f'      sha256 "{sha_macos_arm64}"\n'
    '    end\n'
    '    on_intel do\n'
    f'      url "{base}/kgateway-{ver}-darwin-x86_64.tar.gz"\n'
    f'      sha256 "{sha_macos_x64}"\n'
    '    end\n'
    '  end\n'
    '\n'
    '  on_linux do\n'
    '    on_arm do\n'
    f'      url "{base}/kgateway-{ver}-linux-arm64-musl.tar.gz"\n'
    f'      sha256 "{sha_linux_arm64}"\n'
    '    end\n'
    '    on_intel do\n'
    f'      url "{base}/kgateway-{ver}-linux-x86_64-musl.tar.gz"\n'
    f'      sha256 "{sha_linux_x64}"\n'
    '    end\n'
    '  end\n'
    '\n'
    '  def install\n'
    '    bin.install "kgateway"\n'
    '  end\n'
    '\n'
    '  test do\n'
    '    assert_match "kgateway", shell_output("#{bin}/kgateway --version")\n'
    '  end\n'
    'end\n'
)

out = "Formula/kgateway.rb"
with open(out, "w") as f:
    f.write(formula)
print(f"Written {out} for v{ver}")
