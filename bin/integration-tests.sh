#!/bin/sh

################################################################################
# This script runs the integration tests in Bitbucket Pipelines.
################################################################################

./gradlew --build-cache integrationTest --info
