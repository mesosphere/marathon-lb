#!/bin/bash
set -o errexit -o nounset -o pipefail

SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )";
REPO_DIR=$SCRIPTS_DIR/..
HOOKS_DIR=$REPO_DIR/hooks
GIT_HOOKS_DIR=$REPO_DIR/.git/hooks

echo "Installing git hooks...";

for file in $(ls $HOOKS_DIR); do
  echo "Copying $file";
  cp "$HOOKS_DIR/$file" $GIT_HOOKS_DIR/;
  chmod +x "$GIT_HOOKS_DIR/$file";
done

echo "OK";
