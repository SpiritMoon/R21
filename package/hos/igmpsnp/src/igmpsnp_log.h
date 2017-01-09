#ifndef _IGMP_SNP_LOG_H
#define _IGMP_SNP_LOG_H

 
/* syslog line buffer size used in igmp snooping  */
#define IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE	(256)	

 

void igmp_debug_log(const char * fmt, ...);




/**********************************************************************************
 *igmp_snp_syslog_emerg
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_emerg
(
	char *format,...
);



/**********************************************************************************
 *igmp_snp_syslog_alert
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_alert
(
	char *format,...
);

/**********************************************************************************
 *igmp_snp_syslog_crit
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
 void igmp_snp_syslog_crit
(
	char *format,...
);

/**********************************************************************************
 *igmp_snp_syslog_err
 * output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 *
 **********************************************************************************/
void igmp_snp_syslog_err
(
	char *format,...
);


/**********************************************************************************
 *igmp_snp_syslog_warn
 *	output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_warn
(
	char *format,...
);


/**********************************************************************************
 *  igmp_snp_syslog_notice
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_notice
(
	char *format,...
);

/**********************************************************************************
 *  igmp_snp_syslog_notice
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_info
(
	char *format,...
);


/**********************************************************************************
 *igmp_snp_syslog_dbg
 *
 * output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 *
 **********************************************************************************/
void igmp_snp_syslog_dbg
(
	char *format,...
);
 

#endif
