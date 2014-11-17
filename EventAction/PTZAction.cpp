#include "StdAfx.h"
#include "PTZAction.h"
#include "Crypto.h"


#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib,"Iphlpapi.lib")


#define GET_METHOD				"GET %s HTTP/1.1\r\n"
#define HOST_SECTION			"Host: %s\r\n"
#define CONNECTION_SECTION		"Connection: keep-alive\r\n"
#define AUTH_SECTION			"Authorization: Basic %s\r\n"
#define ACCECPT_SECTION			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
#define AGENT_SECTION			"User-Agent: Etrovision/1.2.8 \r\n\r\n"
#define ENCODE_SECTION			"Accept-Encoding: gzip,deflate,sdch\r\n"
#define LANGUAGE_SECTION		"Accept-Language: en-US,en;q=0.8,zh-TW;q=0.6,zh;q=0.4\r\n\r\n"
#define PTZ_PRESET_CGI			"/config/ptz_preset.cgi?name=%d&act=go"
#define PTZ_AUTOSCAN_CGI		"/config/ptz_autorun.cgi?name=scan"

#define IP_ADDRESS_LEN			16
#define MSG_LEN					512

CPTZAction::CPTZAction(void)
{
}

CPTZAction::~CPTZAction(void)
{
}

void CPTZAction::GetCGIString(const PTZAuthenticate& ptzAuthenticate, char* chValue)
{
	char chCGI[125] = {0};
	if (ptzAuthenticate.ptzAction == PTZ_PRESET)
	{
		sprintf_s(chCGI, sizeof(chCGI), PTZ_PRESET_CGI, ptzAuthenticate.ptzPresetPoint);
	}
	else
	{
		sprintf_s(chCGI, sizeof(chCGI), PTZ_AUTOSCAN_CGI);
	}
	sprintf_s(chValue, MSG_LEN, GET_METHOD, chCGI);
}

void CPTZAction::GetAuthEncode(const PTZAuthenticate& ptzAuthenticate, char* chValue)
{
	char chUserPass[125] = {0};
	char chAuthEncode[30] = {0};

	string strUser(ptzAuthenticate.strUserName.begin(),ptzAuthenticate.strUserName.end());
	string strPass(ptzAuthenticate.strPassword.begin(),ptzAuthenticate.strPassword.end());
	int nLen = sprintf_s(chUserPass, sizeof(chUserPass), "%s:%s",strUser.c_str(), strPass.c_str());

	CCrypto cry(CRYPTO_BASE_64);
	string str = cry.GetEncodeString((unsigned char*)chUserPass, nLen);
	sprintf_s(chValue, MSG_LEN, AUTH_SECTION, str.c_str());
}

void CPTZAction::GetIPAddress(const PTZAuthenticate& ptzAuthenticate, char* chValue)
{
	string str( ptzAuthenticate.strIP.begin(), ptzAuthenticate.strIP.end() );
	sprintf_s(chValue, IP_ADDRESS_LEN, str.c_str());
}

bool CPTZAction::CheckICMP(char* chIP)
{
	DWORD dwRetVal = 0;
	HANDLE hIcmpFile = NULL;
	IPAddr ipaddr = INADDR_NONE;
	char  SendData[] = "IP Monitor";
	char ReplyBuffer[128];
	DWORD ReplySize = 0;

	ipaddr = inet_addr(chIP);
	hIcmpFile = IcmpCreateFile();
	if( hIcmpFile != INVALID_HANDLE_VALUE ) 
	{
		ReplySize = 128;
		dwRetVal = IcmpSendEcho( hIcmpFile, ipaddr,(LPVOID)SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, 5 );
		if( dwRetVal > 0 && strlen(ReplyBuffer)) 
		{
			return true;
		}
		else 
		{
			return false;
		}
	}    
	else
	{
		return false;
	}
}

bool CPTZAction::Action()
{
	sockaddr_in webserver;
	int nResult = 0, sockfd = 0, addr_len = sizeof(sockaddr_in);
	char receive_message[MSG_LEN] = {0};
	char chIP[16] = {0};
	char chCGIString[MSG_LEN] = {0};
	char chAuthString[MSG_LEN] = {0};
	char chIPString[MSG_LEN] = {0};
	char send_message[MSG_LEN] = {0};

	int nPort = m_ptzAuthenticate.nPort;
	GetIPAddress(m_ptzAuthenticate, chIP);
	GetCGIString(m_ptzAuthenticate, chCGIString);
	GetAuthEncode(m_ptzAuthenticate, chAuthString);
	sprintf_s(chIPString, sizeof(chIPString), HOST_SECTION, chIP);

	sockfd = socket(AF_INET,SOCK_STREAM,0);
	webserver.sin_family=AF_INET;
	webserver.sin_port=htons(nPort);
	webserver.sin_addr.s_addr=inet_addr(chIP);
	FormatSendMsg(chCGIString, chIPString, chAuthString, send_message);
	
	if (CheckICMP(chIP))
	{
		if (connect(sockfd,(sockaddr*)(&webserver),sizeof(sockaddr)) > 0)
		{
			closesocket(sockfd);
			return false;
		}
	}
	else
	{
		closesocket(sockfd);
		return false;
	}
	int nLens = strlen(send_message);
	nResult = send(sockfd,send_message,nLens, 0);
	if (nLens == nResult)
	{
		fd_set socks;
		struct timeval t;
		FD_ZERO(&socks);
		FD_SET(sockfd,&socks);
		t.tv_sec = 1;
		t.tv_usec = 0;
		if ((nResult=select(sockfd + 1, &socks, NULL, NULL, &t)) >= 0)
		{	
			recvfrom(sockfd, receive_message,sizeof(receive_message), 0 , (sockaddr*)&webserver ,&addr_len);
		}

		closesocket(sockfd);

		if ( nResult >= 0 && strncmp(receive_message, "HTTP/1.0 200 OK", 15) == 0 )
			return true;
		else
			return false;
	}
	else
	{
		closesocket(sockfd);
		return false;
	}
}

void CPTZAction::FormatSendMsg(const char* chCGIString, const char* chIPString, const char* chAuthString, char* chValue)
{
	sprintf_s(chValue, MSG_LEN, "%s%s%s%s",
		chCGIString,
		chIPString,
		/*CONNECTION_SECTION,*/
		chAuthString,
		/*ACCECPT_SECTION,*/
		AGENT_SECTION
		/*ENCODE_SECTION,*/
		/*LANGUAGE_SECTION*/);
}