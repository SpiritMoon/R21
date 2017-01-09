/*******************************************************************************
Copyright (C) Autelan Technology


This software file is owned and distributed by Autelan Technology 
********************************************************************************


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
* wp_eag_login.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
*
*
*
*******************************************************************************/

#include <stdio.h>
#include "cgic.h"
#include <string.h>
#include <stdlib.h>
#include "ws_eag_login.h"
#include "ws_user_manage.h"

FILE *out;

/*redirection*/
int locate(FILE* fp,char *web)
{
	if( fp == NULL || web == NULL )
		return -1;

	fprintf( fp, "<script type='text/javascript'>\n" );
	fprintf( fp, "window.location.href='%s';\n", web );
	fprintf( fp, "</script>\n" );
	return 0;
}

char * replaceStrPart(char *Src, const char * sReplace)
{
	if( Src == NULL || sReplace == NULL )
	{
		return -1;
	}
	char * replace = NULL;
	int partLen = 0;
	replace = strchr(Src, '?');
	if (NULL != replace) {
		//fprintf(stderr,"before replace=%s\n" ,replace );
		partLen = strlen(replace);
		memset(replace, 0, partLen);
	}
	replace = strrchr(Src, '/');
	partLen = strlen(replace);
	memset(replace, 0, partLen);
	//fprintf(stderr,"inner Src=%s\n" ,Src );
	memcpy(replace, sReplace, strlen(sReplace)+1);
	//fprintf(stderr,"later Src=%s\n" ,Src );
	return Src;
}

/*function : send a request pkg to AC auth and wish to get response from that --tangsiqi 2010-1-18*/
int CgiInformAc(char * clientIp, char * serverIp, PKG_TYPE Type, STAuthProcess * pAuthProc,UINT32 pro)
{
		int retErr=0;

		fprintf(out,"CgiInformAc() parameter clientIp:%s, serverIp:%s, Type:0x%x, protocal=%d\n" ,clientIp,serverIp,Type,pro);
		pAuthProc->pSendPkg= createPortalPkg(Type);
		/*malloc STPortalPkg ready to rev data*/
		fprintf(stderr,"CgiInformAc createPortalPkg suc Type is %d\n",Type );
		fprintf(out,"CgiInformAc createPortalPkg suc Type is %d\n",Type );

		pAuthProc->pRevPkg = (STPortalPkg * )malloc(sizeof(STPortalPkg));
		memset(pAuthProc->pRevPkg, 0, sizeof(STPortalPkg));
		

		setAuthType(pAuthProc->pSendPkg, pro);
		
		setPkgUserIP( pAuthProc->pSendPkg, htonl(inet_addr(clientIp)) );

		
		if(sendPortalPkg(pAuthProc->fd, 3, 2000, serverIp, pAuthProc->pSendPkg) < 0 )
		{
			fprintf(stderr,"CgiInformAc sendPortalPkg failed\n" );
			fprintf(out,"CgiInformAc sendPortalPkg failed\n" );

			retErr = -1;
		}
		else
		{
			fprintf(stderr,"CgiInformAc sendPortalPkg suc\n" );
			fprintf(out,"CgiInformAc sendPortalPkg suc\n" );
			
		}
		
		if(getPortalPkg(pAuthProc->fd, 3, &(pAuthProc->pRevPkg))<0)
		{
			fprintf(stderr,"CgiInformAc getPortalPkg failed\n" );
			fprintf(out,"CgiInformAc getPortalPkg failed\n" );
			retErr = -1;
		}
		else
		{
			fprintf(stderr,"CgiInformAc getPortalPkg suc\n" );
			fprintf(out,"CgiInformAc getPortalPkg suc\n" );
			retErr = getErrCode(pAuthProc->pRevPkg);
		}
		
		
		fprintf(stderr,"CgiInformAc getErrCode(stAuth.pRevPkg)=%d\n", retErr );
		fprintf(out,"CgiInformAc getErrCode(stAuth.pRevPkg)=%d\n", retErr );
		
		
		
	return retErr;
}

/*main--tangsiqi 2010-1-18*/
int cgiMain()
{

	int retLogin=-1,retLogout=-1,ret_challege=0,fd=0;/*0--suc,100--timeout, 減方---fail*/
	unsigned short reqID = 0;
	char opt[10]="";
	FILE * fpOut = cgiOut;
	unsigned char chap_item_use[MD5LEN + 2] = {0};
	unsigned char chap_challenge[MD5LEN] = {0};
	MD5_CTX context;
	unsigned char chap_ident=0;
	STPkgAttr *tlvPkgAttr;
	UINT8  tmp[MD5LEN+1];
	char acIp[32] = "";
	char userIp[32] = "";
	char sucUrl[1024] = "";
	char failUrl[1024] = "";
	char IpAddress[32];
	char InterfaceName[30] = "br-wan";

	//char dataStr[1024] = "";

//	FILE *out;
	char name[20] = "wp_item_use_login test";
	out = fopen( "/var/log/wp_item_use_login.log", "w+" );
    if( out != NULL )
        fprintf( out, "Hello %s\n", name );

	fprintf(out,"******** wp_item_use_login.c start ******** \n");

	
	STUserInfo userInfo;
	memset(&userInfo, 0 ,sizeof(STUserInfo));

	cgiHeaderContentType("text/html");

	/*rev user info from login.html*/
	cgiFormStringNoNewlines("op_auth", opt, 10);

	fprintf(out,"opt_auth=%s\n",opt);
	
	fprintf(stderr,"opt=%s",opt);
	if( strlen(opt)>0 && (!strcmp(opt,"login")) )
	{
		userInfo.usrOperation = 1;
	}
	else
	{
		userInfo.usrOperation = 2;/*logout*/
	}
	
	memset(acIp, 0, sizeof(acIp));
#if 0
	if( cgiFormNotFound == cgiFormStringNoNewlines("wlanacip", acIp, sizeof(acIp)) ) {
		get_ip_addr_by_interface_name(InterfaceName, IpAddress, sizeof(IpAddress));
		fprintf(out,"InterfaceName: %s  IpAddress: %s\n",InterfaceName,IpAddress);
		strncpy(acIp, IpAddress, sizeof(acIp)-1);
		//strncpy(acIp, "3.4.5.6", sizeof(acIp)-1);
	}
#endif
	strncpy(acIp, "127.0.0.1", sizeof(acIp)-1);
	memset(userIp, 0, sizeof(userIp));
	if( cgiFormNotFound == cgiFormStringNoNewlines("wlanuserip", userIp, sizeof(userIp)) ) {
		strncpy(userIp, cgiRemoteAddr, sizeof(userIp)-1);
	}

	memset(sucUrl, 0, sizeof(sucUrl));
	cgiFormStringNoNewlines("suc_url", sucUrl, sizeof(sucUrl));
	memset(failUrl, 0, sizeof(failUrl));
	cgiFormStringNoNewlines("fail_url", failUrl, sizeof(failUrl));

	fprintf( fpOut, "<html xmlns=\"http://www.w3.org/1999/xhtml\"> \n" );
	fprintf( fpOut, "<head> \n" );
	fprintf( fpOut, "<meta http-equiv=Content-Type content=text/html; charset=gb2312> \n" );


  	fprintf( fpOut, "<META   HTTP-EQUIV=\"pragma\"   CONTENT=\"no-cache\"> \n");
  	fprintf( fpOut, "<META   HTTP-EQUIV=\"Cache-Control\"   CONTENT=\"no-cache,   must-revalidate\"> \n" );
  	fprintf( fpOut, "<META   HTTP-EQUIV=\"expires\"   CONTENT=\"Wed,   26   Feb   1997   08:21:57   GMT\">	\n");


	fprintf( fpOut, "<title>login_proc</title>\n");
	fprintf( fpOut, "</head> \n" );
	fprintf( fpOut, "<boby>\n");

	//fprintf( fpOut, "wlanacip=%s,wlanuserip=%s\n", acIp, userIp);
	/*process http req and require a auth request with AC*/
	STAuthProcess stAuth;
	memset(&stAuth, 0, sizeof(STAuthProcess));

	cgi_auth_init(&stAuth, 2000);
	STUserManagePkg * pstReq = NULL;
	STUserManagePkg * pstRsp = NULL;
	char urlPost[4096]={0};
	char *urlNew = NULL;
	char *replace = NULL;

	fprintf(out,"op_auth=%s--giRemoteAddr =%s--cgiServerName=%s\n", opt, cgiRemoteAddr,cgiServerName  );
	
	fprintf(stderr,"op_auth=%s--cgiRemoteAddr =%s--cgiServerName=%s\n", opt, cgiRemoteAddr,cgiServerName  );
	#if 1

	fprintf(stderr,"cgiReferrer=%s\n", cgiReferrer  );

	fprintf(out,"cgiReferrer=%s\n", cgiReferrer  );
	#endif
	strncpy(urlPost, cgiReferrer, strlen(cgiReferrer));
	#if 0
	fprintf(stderr,"before urlPost=%s\n" ,urlPost );
	replace = strrchr(urlPost, '//');
	fprintf(stderr,"before replace=%s\n" ,replace );
	int partLen = strlen(replace);
	memset(replace, "\0", partLen);
	fprintf(stderr,"inner urlPost=%s\n" ,urlPost );
	memcpy(replace, "/auth_suc.html", strlen("/auth_suc.html")+1);
	
	fprintf(stderr,"last urlPost=%s--partLen=%d\n" ,urlPost, partLen );
	#endif
	fprintf(out,"userInfo.usrOperation=%d\n" ,userInfo.usrOperation );
	
	fprintf(stderr,"userInfo.usrOperation=%d\n" ,userInfo.usrOperation );
	switch(userInfo.usrOperation)
	{
		case 1:/*login*/
			//stAuth.protocal = AUTH_CHAP;
			
			pstReq =  createRequirePkg(REQ_GET_AUTH_TYPE,NULL,NULL);
	#if 0
			/*connect unix sock to get auth type*/
			fd = suc_connect_unix_sock();
			fprintf(fpOut,"fd=%d",fd);
			if(fd <= -1)
				break;
	#endif	
			stAuth.protocal = AUTH_CHAP;//get_authType_from_eag( pstReq, fd, 5, &(pstRsp));
			fprintf(out,"stAuth.protocal=0x%x\n",stAuth.protocal);

			fprintf(stderr,"stAuth.protocal=%d",stAuth.protocal);
			close( fd );
			if( stAuth.protocal == AUTH_CHAP )				/*chap md5 simulation----------*/
			{
				fprintf(out,"ret_challege() parameter userIp:%s, acIp:%s, stAuth.protocal=%d\n" ,userIp,acIp,stAuth.protocal);
				ret_challege = CgiInformAc(userIp, acIp, REQ_CHALLENGE, &stAuth, stAuth.protocal);
				fprintf(out,"ret_challege=%d\n", ret_challege);

				fprintf(stderr,"ret_challege=%d", ret_challege);
				if( CHALLENGE_SUCCESS == ret_challege || CHALLENGE_CONNECTED == ret_challege )/*if ret is success ,then can get attr from rev pkg*/
				{
					if((tlvPkgAttr = getAttrByAttrType(stAuth.pRevPkg, ATTR_CHALLENGE)) == NULL && CHALLENGE_CONNECTED == ret_challege)
					{
						retLogin = 0;/*容僕suc.html*/
						break;
					}
				}
				else
				{
					retLogin = -1;/*容僕fail.html*/
					break;
				}
				memcpy(chap_challenge, tlvPkgAttr->attr_value, tlvPkgAttr->attr_len);

				fprintf(out,"chap_challenge() value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", \
						 chap_challenge[0],chap_challenge[1],chap_challenge[2],
						chap_challenge[3],chap_challenge[4],chap_challenge[5],chap_challenge[6],chap_challenge[7],chap_challenge[8],chap_challenge[9],
						chap_challenge[10],chap_challenge[11],chap_challenge[12],chap_challenge[13],chap_challenge[14],chap_challenge[15] );
				
				fprintf(stderr,"chap_challenge() value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", \
						 chap_challenge[0],chap_challenge[1],chap_challenge[2],
						chap_challenge[3],chap_challenge[4],chap_challenge[5],chap_challenge[6],chap_challenge[7],chap_challenge[8],chap_challenge[9],
						chap_challenge[10],chap_challenge[11],chap_challenge[12],chap_challenge[13],chap_challenge[14],chap_challenge[15] );
				reqID = getRequireID(stAuth.pRevPkg);
				fprintf(out,"CHAP: reqID=%d\n",reqID);

				fprintf(stderr,"CHAP: reqID=%d\n",reqID);
				unsigned char chap_id = (unsigned char)reqID ;

				fprintf(out, "chap_id=%d\n",chap_id);

				fprintf(stderr, "chap_id=%d\n",chap_id);

				/*simulate MD5 encoded at portal server add by niehongyan 2016-3-25*/

				MD5Init(&context);
				MD5Update(&context, (UINT8 *)&chap_id, 1);
				MD5Update(&context, chap_challenge, MD5LEN);
				MD5Final(tmp, &context);
				tmp[MD5LEN] = 0;/*add 0 at end of char[]*/
				
				fprintf(out,"CHAP: tmp=%s\n",tmp);
				fprintf(out,"CHAP: tmp=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",tmp[0],tmp[1],tmp[2],
						tmp[3],tmp[4],tmp[5],tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11],tmp[12],tmp[13],tmp[14],tmp[15]);

				fprintf(stderr,"CHAP: tmp=%s",tmp);

				memcpy(chap_item_use, tmp, MD5LEN );
				chap_item_use[MD5LEN+1] = 0;
				fprintf(out,"...add attr CHAP_ITEM_USE() value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", \
						 chap_item_use[0],chap_item_use[1],chap_item_use[2],
						chap_item_use[3],chap_item_use[4],chap_item_use[5],chap_item_use[6],chap_item_use[7],chap_item_use[8],chap_item_use[9],
						chap_item_use[10],chap_item_use[11],chap_item_use[12],chap_item_use[13],chap_item_use[14],chap_item_use[15] );

				fprintf(stderr,"...add attr CHAP_ACCESSCODE() value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", \
					 chap_item_use[0],chap_item_use[1],chap_item_use[2],
					chap_item_use[3],chap_item_use[4],chap_item_use[5],chap_item_use[6],chap_item_use[7],chap_item_use[8],chap_item_use[9],
					chap_item_use[10],chap_item_use[11],chap_item_use[12],chap_item_use[13],chap_item_use[14],chap_item_use[15] );

				destroyPortalPkg(stAuth.pSendPkg);
				destroyPortalPkg(stAuth.pRevPkg);

			}

			/*after challege exchange*/
			stAuth.pSendPkg = createPortalPkg(REQ_AUTH);
			fprintf(out,"login createPortalPkg suc\n" );

			fprintf(stderr,"login createPortalPkg suc\n" );
			
			/*malloc STPortalPkg ready to rev data*/
			stAuth.pRevPkg = (STPortalPkg * )malloc(sizeof(STPortalPkg));
			memset(stAuth.pRevPkg, 0, sizeof(STPortalPkg));
			
			setAuthType(stAuth.pSendPkg, stAuth.protocal);
			setRequireID(stAuth.pSendPkg, reqID );
			setPkgUserIP( stAuth.pSendPkg, htonl(inet_addr(userIp)) );
					
			if( stAuth.protocal == AUTH_CHAP )
			{
				/*challenge exchange*/
				addAttr( &stAuth.pSendPkg, ATTR_ACCESSCODE, chap_item_use, MD5LEN );
				
			}
			if(sendPortalPkg(stAuth.fd, 3, 2000, acIp, stAuth.pSendPkg) < 0 )
			{
				fprintf(out,"login sendPortalPkg failed\n" );

				fprintf(stderr,"login sendPortalPkg failed\n" );
				retLogin = -1;
			}
			else
			{
				fprintf(out,"login sendPortalPkg suc\n" );

				fprintf(stderr,"login sendPortalPkg suc\n" );
			}
			
			if(getPortalPkg(stAuth.fd, 3, &(stAuth.pRevPkg))<0)
			{
				fprintf(out,"login getPortalPkg failed\n" );

				fprintf(stderr,"login getPortalPkg failed\n" );
				retLogin = -1;
			}
			else
			{
				fprintf(out,"login getPortalPkg suc\n" );

				fprintf(stderr,"login getPortalPkg suc\n" );
			}
			retLogin = getErrCode(stAuth.pRevPkg);
			fprintf(out,"login getErrCode(stAuth.pRevPkg)=%d\n", retLogin );

			fprintf(stderr,"login getErrCode(stAuth.pRevPkg)=%d\n", retLogin );
			
			
			destroyPortalPkg(stAuth.pSendPkg);
			destroyPortalPkg(stAuth.pRevPkg);

			/* adding aff_ack_auth package  */
			// err_code=0 means ack-auth normal succeed
			if (0 == retLogin ) { 
				/*after auth exchange*/
				stAuth.pSendPkg = createPortalPkg(AFF_ACK_AUTH);
				
				/*malloc STPortalPkg ready to rev data*/
				stAuth.pRevPkg = (STPortalPkg * )malloc(sizeof(STPortalPkg));
				memset(stAuth.pRevPkg, 0, sizeof(STPortalPkg));
				
				setAuthType(stAuth.pSendPkg, stAuth.protocal);
				setRequireID(stAuth.pSendPkg, reqID );
				setPkgUserIP( stAuth.pSendPkg, htonl(inet_addr(userIp)) );

				if(sendPortalPkg(stAuth.fd, 3, 2000, acIp, stAuth.pSendPkg) < 0 )
				{
					fprintf(out,"auth sendPortalPkg failed\n" );

					fprintf(stderr,"auth sendPortalPkg failed\n" );
					retLogin = -1;
				}
				else
				{
					fprintf(out,"auth sendPortalPkg suc\n" );

					fprintf(stderr,"auth sendPortalPkg suc\n" );
				}
		
				destroyPortalPkg(stAuth.pSendPkg);
				destroyPortalPkg(stAuth.pRevPkg);
			}
			break;
		case 2:/*logout*/
			retLogout = CgiInformAc(userIp, acIp, REQ_LOGOUT, &stAuth, stAuth.protocal);
			destroyPortalPkg(stAuth.pSendPkg);
			destroyPortalPkg(stAuth.pRevPkg);
			break;
		default: break;
	}
	
	fprintf(out,"retLogin=%d---retLogout=%d\n" ,retLogin,retLogout );
	
	fprintf(stderr,"retLogin=%d---retLogout=%d\n" ,retLogin,retLogout );
	closePkgSock(&stAuth);
	if( retLogin==100 ||  retLogout==100 )/*time out will retry,reserve*/
	{
		fprintf( fpOut, "<table border=0 cellspacing=0 cellpadding=0><tr><td colspan=2>time out!please retry or return</td></tr>\n");
		fprintf( fpOut, "<tr><td><input type='submit' name='retry' value='retry'></td><td><input type='submit' name='return' value='return'></td></tr>\n");
		fprintf( fpOut, "</table>\n");
		goto html_end;
	}
#if 0
	memset(dataStr, 0, sizeof(dataStr));
    snprintf(dataStr, sizeof(dataStr), "?wlanacip=%s&wlanuserip=%s", acIp, userIp);
	strncat(sucUrl, dataStr, strlen(dataStr)+1);
	strncat(failUrl, dataStr, strlen(dataStr)+1);
#endif
	if( userInfo.usrOperation == 1 )/*login*/
	{
		switch(retLogin)
		{
			case PORTAL_AUTH_SUCCESS: 	//locate(fpOut, sucUrl);break;
			case PORTAL_AUTH_CONNECTED: //locate(fpOut, sucUrl);break;
				if (0 == strlen(sucUrl)) {
					locate(fpOut, replaceStrPart(urlPost, "/auth_suc.html"));
				} else {
					locate(fpOut, sucUrl);
				}
				break;
			case PORTAL_AUTH_REJECT: 	//locate(fpOut, failUrl);break;
			case PORTAL_AUTH_ONAUTH: 	//locate(fpOut, failUrl);break;
			case PORTAL_AUTH_FAILED: 	//locate(fpOut, failUrl);break;
			case -1:					//locate(fpOut, failUrl);break;
				if (0 == strlen(failUrl)) {
					locate(fpOut, replaceStrPart(urlPost, "/auth_fail.html"));
				} else {
					locate(fpOut, failUrl);
				}
				break;
			default:
				break;
		}
	}
	else if( userInfo.usrOperation == 2 )/*logout*/
	{
		switch(retLogout)
		{
			case EC_ACK_LOGOUT_SUCCESS: //locate(fpOut, sucUrl);break;
				if (0 == strlen(sucUrl)) {
					locate(fpOut, replaceStrPart(urlPost, "/login.html"));
				} else {
					locate(fpOut, sucUrl);
				}
				break;
			case -1:
			case EC_ACK_LOGOUT_REJECT: 	//locate(fpOut, sucUrl);break;
			case EC_ACK_LOGOUT_FAILED: 	//locate(fpOut, failUrl);break;
				if (0 == strlen(failUrl)) {
					locate(fpOut, replaceStrPart(urlPost, "/auth_suc.html"));
				} else {
					locate(fpOut, failUrl);
				}
				break;
			default:
				break;
		}
	}
html_end:

	fprintf( fpOut, "</body>\n" );
	fprintf( fpOut, "</html>\n" );

		
}

