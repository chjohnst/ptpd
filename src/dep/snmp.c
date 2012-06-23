/*-
 * Copyright (c) 2012 The IMS Company
 *                    Vincent Bernat
 *
 * All Rights Reserved
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file   snmp.c
 * @author Vincent Bernat <bernat@luffy.cx>
 * @date   Sat Jun 23 23:08:05 2012
 *
 * @brief  SNMP related functions
 */

#include "../ptpd.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/* Hard to get header... */
extern int header_generic(struct variable *, oid *, size_t *, int,
			  size_t *, WriteMethod **);

#define PTPBASE_SYSTEM_PROFILE 3

#define SNMP_LOCAL_VARIABLES			\
	static unsigned long long_ret;		\
	static U64 counter64_ret;		\
	(void)long_ret;				\
	(void)counter64_ret
#define SNMP_COUNTER64(V)			\
	( counter64_ret.low = (V) & 0xffffffff,	\
	  counter64_ret.high = (V) >> 32,	\
	  *var_len = sizeof (counter64_ret),	\
	  (u_char*)&counter64_ret )
#define SNMP_INTEGER(V)		    \
	( long_ret = (V),	    \
	  *var_len = sizeof (long_ret),		\
	  (u_char*)&long_ret )

/**
 * Handle SNMP scalar values.
 */
static u_char*
snmpScalars(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method) {
    SNMP_LOCAL_VARIABLES;

    if (header_generic(vp, name, length, exact, var_len, write_method))
	    return NULL;

    switch (vp->magic) {
    case PTPBASE_SYSTEM_PROFILE:
	    return SNMP_INTEGER(1);
    }

    return NULL;
}

/**
 * MIB definition
 */
static struct variable4 snmpVariables[] = {
	/* Scalars */
	{ PTPBASE_SYSTEM_PROFILE, ASN_INTEGER, RONLY,
	  snmpScalars, 3, {1, 1, 3}},
};

/**
 * Log messages from NetSNMP subsystem.
 */
static int
snmpLogCallback(int major, int minor,
		void *serverarg, void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message *)serverarg;
	char *msg = strdup (slm->msg);
	if (msg) msg[strlen(msg)-1] = '\0';

	switch (slm->priority)
	{
	case LOG_EMERG:   EMERGENCY("snmp[emerg]: %s\n",   msg?msg:slm->msg); break;
	case LOG_ALERT:   ALERT    ("snmp[alert]: %s\n",   msg?msg:slm->msg); break;
	case LOG_CRIT:    CRITICAL ("snmp[crit]: %s\n",    msg?msg:slm->msg); break;
	case LOG_ERR:     ERROR    ("snmp[err]: %s\n",     msg?msg:slm->msg); break;
	case LOG_WARNING: WARNING  ("snmp[warning]: %s\n", msg?msg:slm->msg); break;
	case LOG_NOTICE:  NOTICE   ("snmp[notice]: %s\n",  msg?msg:slm->msg); break;
	case LOG_INFO:    INFO     ("snmp[info]: %s\n",    msg?msg:slm->msg); break;
	case LOG_DEBUG:   DBGV     ("snmp[debug]: %s\n",   msg?msg:slm->msg); break;
	}
	free(msg);
	return SNMP_ERR_NOERROR;
}

/**
 * Initialisation of SNMP subsystem.
 */
void
snmpInit() {
	static oid ptp_oid[] = {1, 3, 6, 1, 4, 1, 39178, 100, 2};
	netsnmp_enable_subagent();
	snmp_disable_log();
	snmp_enable_calllog();
	snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			       SNMP_CALLBACK_LOGGING,
			       snmpLogCallback,
			       NULL);
	init_agent("ptpAgent");
	REGISTER_MIB("ptpMib", snmpVariables, variable4, ptp_oid);
	init_snmp("ptpAgent");
}
