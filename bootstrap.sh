#!/bin/sh

MAGNUM_SERVER=%{magnum_server}
AFL_VERSION=%{afl_version}

yum install gcc make

mkdir /dev/shm/magnum
cd /dev/shm/magnum

cat >client.crt <<EOF
%{client_cert}
EOF

chmod 644 client.crt

cat >client.key <<EOF
%{client_key}
EOF

chmod 640 client.key

cat >CA.crt <<EOF
%{ca_cert}
EOF

chmod 644 CA.crt

sudo adduser -M -U magnum
chgrp magnum client.key

wget --ca-certificate=CA.crt https://${MAGNUM_SERVER}/static/afl-$AFL_VERSION.tgz https://${MAGNUM_SERVER}/static/magnum

tar -xvzf afl-${AFL_VERSION}.tgz
cd afl-${AFL_VERSION}
make install

cd ..

sudo --background -u magnum ./magnum fuzzball --cert=client.crt --key=client.key --ca=CA.crt ${MAGNUM_SERVER}
