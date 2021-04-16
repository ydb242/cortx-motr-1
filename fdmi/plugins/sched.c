/* -*- C -*- */
/*
* Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* For any questions about this software or licensing,
* please email opensource@seagate.com or cortx-questions@seagate.com.
*
*/

#define M0_TRACE_SUBSYSTEM M0_TRACE_SUBSYS_FDMI

#include "fdmi/plugins/sched.h"

static void usage(void)
{
	m0_console_printf(
		"Usage: m0sched "
		"-l local_addr -h ha_addr -p profile_fid -f process_fid \n"
		"Use -? or -i for more verbose help on common arguments.\n"
		"Usage example for common arguments: \n"
		"m0sched -l 192.168.52.53@tcp:12345:4:1 "
		"-h 192.168.52.53@tcp:12345:1:1 "
		"-p 0x7000000000000001:0x37 -f 0x7200000000000001:0x19"
		"\n");
}

/**
 * @retval 0      Success.
 * @retval -Exxx  Error.
 */

static int
sched_args_parse(struct sched_conf *params, int argc, char ** argv)
{
	int    rc = 0;

	params->local_addr 	= NULL;
	params->ha_addr    	= NULL;
	params->profile_fid     = NULL;
	params->process_fid   	= NULL;

	rc = M0_GETOPTS("m0sched", argc, argv,
			M0_HELPARG('?'),
			M0_VOIDARG('i', "more verbose help",
					LAMBDA(void, (void) {
						usage();
						exit(0);
					})),
			M0_STRINGARG('l', "Local endpoint address",
					LAMBDA(void, (const char *string) {
					params->local_addr = (char*)string;
					})),
			M0_STRINGARG('h', "HA address",
					LAMBDA(void, (const char *str) {
						params->ha_addr = (char*)str;
					})),
			M0_STRINGARG('f', "Process FID",
					LAMBDA(void, (const char *str) {
						params->process_fid = (char*)str;
					})),
			M0_STRINGARG('p', "Profile options for Client",
					LAMBDA(void, (const char *str) {
						params->profile_fid = (char*)str;
					})));
	if (rc != 0)
		return M0_ERR(rc);
	/* All mandatory params must be defined. */
	if (rc == 0 &&
	    (params->local_addr == NULL || params->ha_addr == NULL ||
	     params->profile_fid == NULL || params->process_fid == NULL)) {
		usage();
		rc = M0_ERR(-EINVAL);
	}

	return rc;
}

static int sched_init(struct sched_conf *conf)
{
	int rc;
	m0_conf.mc_local_addr            = conf->local_addr;
	m0_conf.mc_ha_addr               = conf->ha_addr;
	m0_conf.mc_profile               = conf->profile_fid;
	m0_conf.mc_process_fid           = conf->process_fid;
	m0_conf.mc_tm_recv_queue_min_len = M0_NET_TM_RECV_QUEUE_DEF_LEN;
	m0_conf.mc_max_rpc_msg_size      = M0_RPC_DEF_MAX_RPC_MSG_SIZE;
	m0_conf.mc_layout_id             = 1;
	m0_conf.mc_is_oostore            = 1;
	m0_conf.mc_is_read_verify        = 0;
	m0_conf.mc_idx_service_id        = M0_IDX_DIX;

	dix_conf.kc_create_meta 	 = false;
	m0_conf.mc_idx_service_conf 	 = &dix_conf;

	/* Client instance */
	rc = m0_client_init(&m0_instance, &m0_conf, true);
	if (rc != 0) {
		fprintf(stderr, "Failed to initialise Client: %d\n", rc);
		goto do_exit;
	}

	M0_POST(m0_instance != NULL);

	/* And finally, client root realm */
	m0_container_init(&container,
				 NULL, &M0_UBER_REALM,
				 m0_instance);

	rc = container.co_realm.re_entity.en_sm.sm_rc;
	if (rc != 0) {
		fprintf(stderr, "Failed to open uber realm\n");
		goto do_exit;
	}

	M0_POST(container.co_realm.re_instance != NULL);
	uber_realm = container.co_realm;
do_exit:
	return rc;
}

static void sched_fini()
{
	m0_client_fini(m0_instance, true);
}
/*
 * ---------------------------------------------------------------------
 * signal handling
 */

static void sched_sighandler(int signum)
{
	fprintf(stdout, "m0sched Interrupted by signal %d\n", signum);
	m0_semaphore_up(&sched_sem);
	/* Restore default handlers. */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

}

static int sched_sighandler_init(void)
{
	struct sigaction sa = { .sa_handler = sched_sighandler };
	int              rc;

	sigemptyset(&sa.sa_mask);
	/* Block these signals while the handler runs. */
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGTERM);

	rc = sigaction(SIGINT, &sa, NULL) ?: sigaction(SIGTERM, &sa, NULL);
	return rc == 0 ? 0 : M0_ERR(errno);
}

void print_params(struct sched_conf *params) {
	printf("local: %s\n", params->local_addr);
	printf("ha: %s\n", params->ha_addr);
	printf("prof: %s\n", params->profile_fid);
	printf("process: %s\n", params->process_fid);
}

int main(int argc, char **argv)
{
	int rc = 0;
	if (argc == 1) {
		fprintf(stderr, "Arguments are not provided.\n");
		exit(EXIT_FAILURE);
	}
	rc = sched_args_parse(&c_params, argc, argv);
	if (rc != 0) {
		fprintf(stderr, "Sched args parse failed\n");
		return M0_ERR(errno);
	}
	rc = m0_semaphore_init(&sched_sem, 0);
	if (rc != 0)
		return M0_ERR(errno);

	//print_params(&c_params);

	rc = sched_init(&c_params);
	if (rc != 0) {
		sched_fini();
		return M0_ERR(errno);
	}

	rc = sched_sighandler_init();
	if (rc != 0)
		goto sem_fini;
	/* main thread loop */
	fprintf(stdout, "m0sched waiting for signal...\n");
	m0_semaphore_down(&sched_sem);
sem_fini:
	m0_semaphore_fini(&sched_sem);
	sched_fini();
	return M0_RC(rc < 0 ? -rc : rc);
}

#undef M0_TRACE_SUBSYSTEM
/** @} m0sched */
