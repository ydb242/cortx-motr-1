/* -*- C -*- */
/*
 * Copyright (c) 2011-2020 Seagate Technology LLC and/or its Affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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


#include <linux/module.h>

#include "rpc_ping.h"
#include "lib/thread.h"

M0_INTERNAL int init_module(void)
{
	M0_THREAD_ENTER;
	return m0_rpc_ping_init();
}

M0_INTERNAL void cleanup_module(void)
{
	M0_THREAD_ENTER;
	m0_rpc_ping_fini();
}

/*
 * We are using Apache license for complete motr code but for MODULE_LICENSE
 * marker there is no provision to mention Apache for this marker. But as this
 * marker is necessary to remove the warnings, keeping this blank to make
 * compiler happy.
 */
MODULE_LICENSE();

/*
 *  Local variables:
 *  c-indentation-style: "K&R"
 *  c-basic-offset: 8
 *  tab-width: 8
 *  fill-column: 80
 *  scroll-step: 1
 *  End:
 */
