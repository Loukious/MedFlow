#!/usr/bin/env bash
set -euo pipefail

install_nuclei() {
  if command -v nuclei >/dev/null 2>&1; then
    nuclei -version || true
    return
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"

  sudo apt-get update
  sudo apt-get install -y curl unzip ca-certificates

  local url
  url="$(
    curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest |
      grep browser_download_url |
      grep linux_amd64.zip |
      head -1 |
      cut -d '"' -f 4
  )"
  if [[ -z "$url" ]]; then
    echo "Could not discover the latest Nuclei linux_amd64 release URL." >&2
    return 1
  fi

  curl -fsSL "$url" -o "$tmpdir/nuclei.zip"
  unzip -q "$tmpdir/nuclei.zip" -d "$tmpdir/nuclei"
  sudo install -m 0755 "$tmpdir/nuclei/nuclei" /usr/local/bin/nuclei
  rm -rf "$tmpdir"
  nuclei -version || true
}

install_metasploit() {
  if command -v msfconsole >/dev/null 2>&1; then
    msfconsole -v || true
    return
  fi

  sudo apt-get update
  if apt-cache show metasploit-framework >/dev/null 2>&1; then
    sudo apt-get install -y metasploit-framework
  else
    cat >&2 <<'EOF'
metasploit-framework is not available from the current apt sources.
Install Metasploit Framework from Rapid7's official Linux package instructions,
then rerun the lab. The MedFlow runner will automatically use msfconsole once it
is on PATH.
EOF
    return 1
  fi
}

main() {
  local tool="${1:-all}"
  case "$tool" in
    all)
      install_nuclei
      install_metasploit
      ;;
    nuclei)
      install_nuclei
      ;;
    metasploit)
      install_metasploit
      ;;
    *)
      echo "Usage: $0 [all|nuclei|metasploit]" >&2
      return 2
      ;;
  esac
}

main "$@"
