#!/bin/sh

################################################################################
# This script publishes the final artifact to a Maven repository.
################################################################################

# A snapshot verson is expected to end with SNAPSHOT. i.e. 1.0-SNAPSHOT. Release versions will exclude the SNAPSHOT postfix.
SNAPSHOT_VERSION=$(./gradlew properties -q | grep "^version:" | awk '{print $2}')
RELEASE_VERSION=$(echo "$SNAPSHOT_VERSION" | cut -d'-' -f 1)

# Determine the artifact version based on the deployment stage.
printf "BITBUCKET_DEPLOYMENT_ENVIRONMENT: %s\n" "$BITBUCKET_DEPLOYMENT_ENVIRONMENT"
DEPLOYMENT_STAGE=$(echo "$BITBUCKET_DEPLOYMENT_ENVIRONMENT" | tr '[:upper:]' '[:lower:]') # development or production

ARTIFACT_VERSION=$([ "$DEPLOYMENT_STAGE" = "production" ] && echo "$RELEASE_VERSION" || echo "$SNAPSHOT_VERSION")

./gradlew --build-cache publish -Pversion="${ARTIFACT_VERSION}" --info
