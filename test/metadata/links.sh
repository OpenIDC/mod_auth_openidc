#!/bin/sh

#for d in `ls -d */` ; do
for d in "dynamic/" ; do
  cd $d
  echo "#"
  echo $d
  echo "#"
  for f in `ls rp-*.conf` ; do
    for s in rp_test rp.certification.openid.net ; do
      ln -s $f ${s}%3A8080%2Fmod_auth_openidc-${d%%/}%2F$f
    done
  done
  cd -
done
