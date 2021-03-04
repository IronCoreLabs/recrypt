#!/bin/bash

# If any of the commands fail, fail this whole script
set -e

PUBLISH=false
ROOT_PUBLISH_DIR=$(dirname "$0")

function ensure_up_to_date_main_branch() {
    # Force current branch to be main when publishing
    if [ "$(git symbolic-ref --short -q HEAD)" != "main" ]; then
        echo "Library can only be published off 'main'."
        exit -1
    fi

    # fetch any changes from remote, then compare revisions. If they don't match, abort.
    git fetch
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse '@{u}')" ]; then
        echo "Local repo and origin are out of sync! Have you pushed all your changes? Have you pulled the latest?"
        exit -1
    fi

    # ensure the checkout is clean
    if [[ -n $(git status --porcelain) ]]; then
        echo "This git repository is has uncommitted files. Publish aborted!"
        exit -1
    fi
}

for i in "$@"
do
    case $i in
        -h|--help)
            echo ""
            echo "    Deploy script to publish recryptjs library to NPM. If doing dry runs, you'll need 'irish-pub' installed 'npm install -g irish-pub'"
            echo ""
            echo "    Usage: ./deploy.sh"
            echo "        Options:"
            echo "            --publish - If provided, library will be published to NPM. Otherwise perform a dry run."
            echo ""
            exit 0
            ;;
        --publish)
            PUBLISH=true
            shift
            ;;
        *)
            echo ""
            echo "  Unknown option ${i#*=}."
            echo ""
            exit 1;
            ;;
    esac
done

if [ "$PUBLISH" == true ]; then
    ensure_up_to_date_main_branch
fi

rm -f "$ROOT_PUBLISH_DIR/index.js"

cd "$ROOT_PUBLISH_DIR"/../../../

SCALA_JS_COMMON_JS=true sbt clean fullOptJS

cp core/js/target/scala-2.12/recrypt-core-opt.js core/js/build/index.js
cp README.md core/js/build/
cp LICENSE core/js/build/

cd core/js/build

if [ "$PUBLISH" == true ]; then
    npm publish --access public
else
    npm publish --dry-run
fi

# Cleanup files that we moved into the build directory
rm LICENSE
rm README.md
rm index.js
