This document contains information about m0sched binary. 

***************
Build
***************

- Setup motr/hare cluster with help of Hare User Guide. Ref - https://github.com/Seagate/cortx-hare/blob/c0ff88671c16c49de1cca81f6d06af180113e72b/README.md

- Once you setup motr/hare cluster, m0sched binary will be available for use. **m0sched** location: fdmi/plugins/m0sched

***************
Exceution
***************

- **m0sched** takes 4 params as command line options, local endpoint address, ha address, profile and process fid, to get these details check **hctl status**.

    ::

    hctl status

- execute **m0sched** with expected commandline options, **m0sched** with option **-?** and **-i** will give you help details.

    ::
    
    m0sched -l 192.168.52.53@tcp:12345:4:1 -h 192.168.52.53@tcp:12345:1:1 -p 0x7000000000000001:0x37 -f 0x7200000000000001:0x19

- execute **m0crate** with dix put workload config file

    ::

    mcrate -S /tmp/m0crate-index.yaml

- Now you can check fol record received at plugin application side ie **m0sched** at /tmp location with file name fol_rec_m0sched*

    ::

    ls -l /tmp/fol_rec_m0sched*
