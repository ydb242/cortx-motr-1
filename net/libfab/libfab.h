/* -*- C -*- */
/*
 * Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
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


#pragma once

#ifndef __MOTR_NET_LIBFAB_LIBFAB_H__
#define __MOTR_NET_LIBFAB_LIBFAB_H__

M0_INTERNAL int  m0_net_libfab_init(void);
M0_INTERNAL void m0_net_libfab_fini(void);

#ifdef ENABLE_LIBFAB
extern struct m0_net_xprt m0_net_libfab_xprt;


#endif /* ENABLE_LIBFAB */
/**
 * @defgroup netlibfab
 *
 * @{
 */

/** @} end of netlibfab group */
#endif /* __MOTR_NET_LIBFAB_LIBFAB_H__ */

/*
 *  Local variables:
 *  c-indentation-style: "K&R"
 *  c-basic-offset: 8
 *  tab-width: 8
 *  fill-column: 80
 *  scroll-step: 1
 *  End:
 */
/*
 * vim: tabstop=8 shiftwidth=8 noexpandtab textwidth=80 nowrap
 */

