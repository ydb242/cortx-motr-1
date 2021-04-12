#pragma once
#ifndef __MOTR_FDMI_PLUGINS_SCHED_H__
#define  __MOTR_FDMI_PLUGINS_SCHED_H__
#include <stdlib.h>
#include <stdio.h>

void m0_sched_init()
{
	printf("%s called\n", __func__);
}

#endif /*  __MOTR_FDMI_PLUGINS_SCHED_H__ */
