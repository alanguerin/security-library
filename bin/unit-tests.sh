#!/bin/sh

################################################################################
# This script runs the unit tests in Bitbucket Pipelines.
################################################################################

./gradlew --build-cache unitTest --info
