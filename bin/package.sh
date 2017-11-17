#!/bin/bash
VERSION=$(cat VERSION)
docker build . -t "stratio/marathon-lb-sec:$VERSION"
