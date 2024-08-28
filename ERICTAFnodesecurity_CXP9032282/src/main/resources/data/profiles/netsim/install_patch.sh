#!/bin/sh

./$1/netsim_shell <<EOF


.install importpatch /netsim/$1/patches/$2.zip
.install patch $2.zip
EOF
