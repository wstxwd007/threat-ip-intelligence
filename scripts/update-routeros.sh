#!/bin/sh
# Set TIPI_* in a root/systemd-protected env file; never put passwords on command line.
set -eu
: "${TIPI_MANIFEST_URL:?set TIPI_MANIFEST_URL}"
: "${TIPI_ROS_URL:?set TIPI_ROS_URL}"
: "${TIPI_ROS_USER:?set TIPI_ROS_USER}"
: "${TIPI_ROS_PASSWORD:?set TIPI_ROS_PASSWORD}"
MODE=""
if [ "${TIPI_ENABLE_APPLY:-no}" = "yes" ]; then
  MODE="--apply --confirm scaners"
fi
# Unquoted $MODE is intentional for the two fixed, internally-controlled flags.
if [ -n "${TIPI_ROS_CA:-}" ]; then
  if [ "$MODE" = "--apply --confirm scaners" ]; then
    exec python3 -m threatip.routeros --manifest-url "$TIPI_MANIFEST_URL" --router-url "$TIPI_ROS_URL" --ca-file "$TIPI_ROS_CA" --apply --confirm scaners
  fi
  exec python3 -m threatip.routeros --manifest-url "$TIPI_MANIFEST_URL" --router-url "$TIPI_ROS_URL" --ca-file "$TIPI_ROS_CA"
fi
if [ "$MODE" = "--apply --confirm scaners" ]; then
  exec python3 -m threatip.routeros --manifest-url "$TIPI_MANIFEST_URL" --router-url "$TIPI_ROS_URL" --apply --confirm scaners
fi
exec python3 -m threatip.routeros --manifest-url "$TIPI_MANIFEST_URL" --router-url "$TIPI_ROS_URL"
