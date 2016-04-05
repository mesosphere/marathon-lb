#!/bin/bash
set -o errexit -o nounset -o pipefail

SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )";
REPO_DIR="$SCRIPTS_DIR/..";
META_DIR="$REPO_DIR/repo/meta"

echo "Building docs...";
$REPO_DIR/"marathon_lb.py" --longhelp > $REPO_DIR/Longhelp.md;
echo "OK";
