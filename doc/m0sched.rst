This document contains information about m0sched binary. 

***************
Build
***************

- Setup motr/hare cluster with help of Hare User Guide. Ref - https://github.com/Seagate/cortx-hare/blob/c0ff88671c16c49de1cca81f6d06af180113e72b/README.md

- Once you setup motr/hare cluster, m0sched binary will be available for use. m0sched location: fdmi/plugins/m0sched

***************
Help
***************

- Takes 4 params as command line option, local endpoint address, ha address, profile and process fid, to get these details check hctl status.

- For example,

[root@devvm temp]# hctl status
Data pool:
    # fid name
    0x6f00000000000001:0x1f 'the_pool'
Profile:
    # fid name: pool(s)
    0x7000000000000001:0x37 'default': 'the_pool' None None
Services:
    localhost  (RC)
    [started]  hax        0x7200000000000001:0x6   192.168.52.53@tcp:12345:1:1
    [started]  confd      0x7200000000000001:0x9   192.168.52.53@tcp:12345:2:1
    [started]  ioservice  0x7200000000000001:0xc   192.168.52.53@tcp:12345:2:2
    [unknown]  m0_client  0x7200000000000001:0x19  192.168.52.53@tcp:12345:4:1
    [unknown]  m0_client  0x7200000000000001:0x1c  192.168.52.53@tcp:12345:4:2

[root@devvm ~]# m0sched -?
Usage: m0sched options...

where valid options are

         -?           : display this help and exit
         -i           : more verbose help
         -l     string: Local endpoint address
         -h     string: HA address
         -f     string: Process FID
         -p     string: Profile options for Client

[root@ssc-vm-2410 ~]# m0sched -i
Usage: ./m0sched -l local_addr -h ha_addr -p profile_fid -f process_fid
Use -? or -i for more verbose help on common arguments.
Usage example for common arguments:
m0sched -l 192.168.52.53@tcp:12345:4:1 -h 192.168.52.53@tcp:12345:1:1 -p 0x7000000000000001:0x37 -f 0x7200000000000001:0x19
