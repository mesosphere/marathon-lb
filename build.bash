#!/bin/bash

set -o errexit -o nounset -o pipefail

if [ $label == 'py27' ]; then
  PIPCMD='pip'
else
  PIPCMD='pip3'
fi

$PIPCMD install -r requirements.txt -r requirements-dev.txt nose

PYTHONPATH=. nosetests
