#!/bin/bash

#set -ex

motr_st_util_dir=$(dirname $(readlink -f $0))
m0t1fs_dir="$motr_st_util_dir/../../../m0t1fs/linux_kernel/st"

M0_SRC_DIR="$motr_st_util_dir/../../../"
. $M0_SRC_DIR/utils/functions # m0_default_xprt

. $m0t1fs_dir/common.sh
. $m0t1fs_dir/m0t1fs_common_inc.sh
. $m0t1fs_dir/m0t1fs_client_inc.sh
. $m0t1fs_dir/m0t1fs_server_inc.sh
. $motr_st_util_dir/motr_local_conf.sh
. $motr_st_util_dir/motr_st_inc.sh

proc_state_change()
{
    local lnet_nid=$(m0_local_nid_get)
    local c_endpoint="$lnet_nid:$M0HAM_CLI_EP"
    local s_endpoint="$lnet_nid:$1"
    local fid=$2
    local state=$3
    local forced_c_endpoint=$4

    # XXX: A work around that allows the user
    # to specify a pair of full endpoints (inet:tcp:A@1 and inet:tcp:B@2)
    # rather than infering portions of it from the system.
    # It is needed to allow this code work with libfab.
    if [[ x"$4" != "x" ]]; then
        if [[ "$1" =~ "inet:tcp:" ]]; then
            c_endpoint=$4
            s_endpoint=$1
        else
            echo "Cannot bypass the endpoint inference"
            echo "  because the server address is not a generic endpoint."
            exit 1
        fi
    fi

    echo "addr=$1, s_endpoint=$s_endpoint, c_endpoint=$c_endpoint" >> /tmp/2
    send_ha_events "$fid" "$state" "$s_endpoint" "$c_endpoint"
}

# {0x72| ((^r|1:12), ..., "192.168.122.122@tcp:12345:2:1", ...
# {0x72| ((^r|1:26), ..., "192.168.122.122@tcp:12345:2:2", ...

function usage()
{
    echo "Usage:"
    echo "$(basename "$0") <target_endpoint> <fid> <state>"
    echo ""
    echo "EXAMPLE: $(basename "$0") \"12345:2:2\" \"^r|1:26\" \"transient\""
    echo "EXAMPLE: $(basename "$0") \"12345:2:3\" \"^r|1:12\" \"online\""
}

#if [ $# -ne 3 ]
#then
    #usage
    #exit 1
#fi

proc_state_change $1 $2 $3 $4 > /dev/null
