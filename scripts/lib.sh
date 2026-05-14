#!/usr/bin/env bash
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[IONA]${NC} $*"; }
ok()   { echo -e "${GREEN}[IONA] ✓${NC} $*"; }
fail() { echo -e "${RED}[IONA] ✗${NC} $*" >&2; }
die()  { fail "$*"; exit 1; }
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT_DIR/dist"
