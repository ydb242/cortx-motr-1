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
#include "lib/trace.h"
#include "fdmi/plugins/sched.h"

#include <unistd.h>           
#include <getopt.h>
#include <errno.h>

/* sched client conf params */
struct sched_conf {
        char *local_addr;
        char *ha_addr;
        char *profile_fid;
        char *process_fid;
}c_params;

static struct m0_semaphore 	sched_sem;
struct m0_config		m0_conf = {};
struct m0_client	       *m0_instance = NULL;
struct m0_container	        container = {};
static struct m0_idx_dix_config dix_conf = {};

/**
 * @retval 0      Success.
 * @retval 1      Help message printed. The program should be terminated.
 * @retval -Exxx  Error.
 */

static int 
sched_args_parse(struct sched_conf *params, int argc, char ** argv)
{
        int  c = 0;
	static struct option opts[] = {
				{"local",         required_argument, NULL, 'l'},
				{"ha",            required_argument, NULL, 'H'},
				{"profile",       required_argument, NULL, 'p'},
				{"process",       required_argument, NULL, 'P'}};
        while ((c = getopt_long(argc, argv, ":l:H:p:P:", opts, NULL)) != -1)
	{
		switch (c) {
			case 'l': params->local_addr = optarg;
				  continue;
			case 'H': params->ha_addr = optarg;
				  continue;
			case 'p': params->profile_fid = optarg;
				  continue;
			case 'P': params->process_fid = optarg;
				  continue;
			case '?': fprintf(stderr, "Unsupported option '%c'\n",
					  optopt);
				  exit(EXIT_FAILURE);
			case ':': fprintf(stderr, "No argument given for '%c'\n",
				          optopt);
				  exit(EXIT_FAILURE);
			default:  fprintf(stderr, "Unsupported option '%c'\n", c);
		}
	}
	return (0);
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
	while (1) {	
		fprintf(stdout, "m0sched Listening...\n");
		m0_semaphore_down(&sched_sem);
	}
sem_fini:
	m0_semaphore_fini(&sched_sem);
	sched_fini();	
	return M0_RC(rc < 0 ? -rc : rc);
}

#undef M0_TRACE_SUBSYSTEM
/** @} m0sched */
