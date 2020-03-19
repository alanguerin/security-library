#!/bin/sh

################################################################################
# This script builds the final artifact in Bitbucket Pipelines.
################################################################################

./gradlew --build-cache build --info
