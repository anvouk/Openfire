#!/usr/bin/env bash
# CALL LIKE SO: bash build/debian/build_debs.sh
set -x

pushd .
# This allows us to pass in the Openfire version from the command-line.
if [ $1 ]; then
    export OPENFIRE_FULLVERSION=$1
else
    export OPENFIRE_FULLVERSION=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
fi
export OPENFIRE_VERSION=$(echo "${OPENFIRE_FULLVERSION}" | cut -d'-' -f1)
export DEBIAN_BUILDDATE="$(date +'%a, %d %b %Y %H:%M:%S %z')"
export WORKDIR_BOF=tmp/debian/openfire-${OPENFIRE_VERSION}

if [ -d "tmp/debian" ]; then
    echo "Removing previous workdir tmp/debian"
    rm -rf tmp/debian
fi
mkdir -p $WORKDIR_BOF

cp -r distribution/target/distribution-base/. $WORKDIR_BOF/

mkdir -p $WORKDIR_BOF/debian
cp build/debian/* $WORKDIR_BOF/debian/
# HACK remove out this actual script
rm -f $WORKDIR_BOF/debian/build_debs.sh

# make rules executable
chmod 755 $WORKDIR_BOF/debian/rules

cd $WORKDIR_BOF/debian
# Do some needed replacements
sed -i.bak s/@version@/${OPENFIRE_VERSION}/g changelog
sed -i.bak s/@builddate@/"${DEBIAN_BUILDDATE}"/g changelog
cd ..
# Disable build-dependencies, because they're often not useful here.
#dpkg-buildpackage -d -rfakeroot -us -uc
dpkg-buildpackage -D -us -uc

pushd
mkdir -p distribution/target/debian
mv tmp/debian/openfire*deb distribution/target/debian/
