set -x
set -e

rm -rf /var/crash/core.0.*
make -j
rm -rf /var/motr/m0ut/*
./utils/m0run    -- "m0ut -k -t idx-dix-mt:dtm0_e_then_s"
rm -f dumps_777.txt
/root/cortx-motr/addb2/m0addb2dump -f -- /var/motr/m0ut/ut-sandbox/cs_addb_stob-*/o/100000000000000\:2 > dumps_777.txt
