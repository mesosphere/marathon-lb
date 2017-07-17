#!/bin/bash

set -o errexit -o nounset -o pipefail

if [ $label == 'py27' ]; then
  PIPCMD='pip'
else
  PIPCMD='pip3'
fi

$PIPCMD install -r requirements-dev.txt

PYTHONPATH=. coverage run "$(which nosetests)"

coverage report

flake8 .
