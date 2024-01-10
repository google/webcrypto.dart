#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$DIR/.."

CHROMEDRIVER='chromedriver'
if which "$CHROMEDRIVER" > /dev/null; then
  echo 'Found chromedriver on PATH'
else
  TARGET="$ROOT/.dart_tool/chromedriver"

  # Detect chrome version
  CHROME_VERSION=$(google-chrome --version | grep -Po '(\d+.\d+.\d+)')
  echo "CHROME_VERSION: $CHROME_VERSION"

  # Create target file
  mkdir -p "$TARGET"
  touch "$TARGET/CHROME_VERSION";

  # Check that chrome haven't been updated
  if [[ $(cat "$TARGET/CHROME_VERSION") != "$CHROME_VERSION" ]]; then
    # Clear cache
    rm -rf "$TARGET"
    mkdir -p "$TARGET"

    # Find matching chromedriver version
    BASE_URL='https://chromedriver.storage.googleapis.com'
    CHROMEDRIVER_VERSION=$(curl -L -s "$BASE_URL/LATEST_RELEASE_$CHROME_VERSION")
    echo "CHROMEDRIVER_VERSION: $CHROMEDRIVER_VERSION"

    # Detect platform
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
      PLATFORM='linux64'
    elif [[ "$OSTYPE" == "darwin"* ]]; then
      PLATFORM='mac64'
    elif [[ "$OSTYPE" == "cygwin" ]]; then
      PLATFORM='win32'
    elif [[ "$OSTYPE" == "msys" ]]; then
      PLATFORM='win32'
    elif [[ "$OSTYPE" == "win32" ]]; then
      PLATFORM='win32'
    else
      echo "Unsupported OSTYPE: $OSTYPE"
      exit 1
    fi

    # Download chromedriver
    curl -L "$BASE_URL/$CHROMEDRIVER_VERSION/chromedriver_$PLATFORM.zip" \
      -o "$TARGET/chromedriver.zip"

    # Extract to target
    unzip "$TARGET/chromedriver.zip" -d "$TARGET"

    # Store CHROME_VERSION so we can easily check if it's outdated
    echo "$CHROME_VERSION" > "$TARGET/CHROME_VERSION"
  fi
  CHROMEDRIVER="$TARGET/chromedriver"
fi

# Start chromedriver and kill it when we exit
"$CHROMEDRIVER" --port=4444 &
CHROMEDRIVER_PID="$!"
trap "kill $CHROMEDRIVER_PID; wait $CHROMEDRIVER_PID 2>/dev/null;" EXIT

# Give chromedriver time to start
sleep 2

# Run whatever command we were told to run
$@
