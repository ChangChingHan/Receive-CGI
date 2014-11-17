#include "StdAfx.h"
#include "SMTPMail.h"
#include "openssl/err.h"
#include "md5.h"

#define SMTP_SENDER_NAME	"Etrovision"
#define SMTP_SUBJECT		_T("Event From CameraIP:%s")
#define SMTP_MESSAGE		_T("Receive event type:%s\n%s")

#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

Command_Entry command_list[] = 
{
	{command_INIT,          0,     5*60,  220, ECSmtp::SERVER_NOT_RESPONDING},
	{command_EHLO,          5*60,  5*60,  250, ECSmtp::COMMAND_EHLO},
	{command_AUTHPLAIN,     5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_PLAIN},
	{command_AUTHLOGIN,     5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_LOGIN},
	{command_AUTHCRAMMD5,   5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_CRAMMD5},
	{command_AUTHDIGESTMD5, 5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_DIGESTMD5},
	{command_DIGESTMD5,     5*60,  5*60,  335, ECSmtp::COMMAND_DIGESTMD5},
	{command_USER,          5*60,  5*60,  334, ECSmtp::UNDEF_XYZ_RESPONSE},
	{command_PASSWORD,      5*60,  5*60,  235, ECSmtp::BAD_LOGIN_PASS},
	{command_MAILFROM,      5*60,  5*60,  250, ECSmtp::COMMAND_MAIL_FROM},
	{command_RCPTTO,        5*60,  5*60,  250, ECSmtp::COMMAND_RCPT_TO},
	{command_DATA,          5*60,  2*60,  354, ECSmtp::COMMAND_DATA},
	{command_DATABLOCK,     3*60,  0,     0,   ECSmtp::COMMAND_DATABLOCK},	// Here the valid_reply_code is set to zero because there are no replies when sending data blocks
	{command_DATAEND,       3*60,  10*60, 250, ECSmtp::MSG_BODY_ERROR},
	{command_QUIT,          5*60,  5*60,  221, ECSmtp::COMMAND_QUIT},
	{command_STARTTLS,      5*60,  5*60,  220, ECSmtp::COMMAND_EHLO_STARTTLS}
};

bool CSMTPMail::SendMail()
{
	USES_CONVERSION;
	CString strSubject,strMsg;
	strSubject.Format(SMTP_SUBJECT, m_eventInfo.tcIP);
	strMsg.Format(SMTP_MESSAGE, GetEventString((EVENTTYPE)m_eventInfo.nEventType),m_EmailContent);

	SetSMTPServer( W2A(m_SMTPInfo.SMTPServer.c_str()), _wtoi(m_SMTPInfo.SMTPPort.c_str()) );
	SetSecurityType(m_SMTPInfo.SMTPSecure);
	SetLogin( W2A(m_SMTPInfo.SMTPAccount.c_str()));
	SetPassword(W2A(m_SMTPInfo.SMTPPassword.c_str()));
	SetSenderName(SMTP_SENDER_NAME);
	SetSenderMail(W2A(m_SMTPInfo.SMTPAccount.c_str()));
	SetSubject(W2A(strSubject));
	AddRecipient(W2A(m_SMTPInfo.SMTPAccount.c_str()));
	SetXPriority(XPRIORITY_NORMAL);
	AddMsgLine(W2A(strMsg));

	return Send();
}

CSMTPMail::CSMTPMail()
{
	hSocket = NULL;
	m_bConnected = false;
	m_iXPriority = XPRIORITY_NORMAL;
	m_iSMTPSrvPort = 0;
	m_bAuthenticate = true;
	m_cry.SetCryptoType(CRYPTO_BASE_64);

	// Initialize WinSock
	WSADATA wsaData;
	WORD wVer = MAKEWORD(2,2);    
	if (WSAStartup(wVer,&wsaData) != NO_ERROR)
		throw ECSmtp(ECSmtp::WSA_STARTUP);
	if (LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsaData.wVersion ) != 2 ) 
	{
		WSACleanup();
		throw ECSmtp(ECSmtp::WSA_VER);
	}

	char* str = NULL;
	if((str = new char[255]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);
	if(gethostname(str,255) == SOCKET_ERROR)
	{
		delete[] str;
		throw ECSmtp(ECSmtp::WSA_HOSTNAME);
	}
	m_sLocalHostName.insert(0,str);
	delete[] str;
	
	if((m_RecvBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);
	
	if((m_SendBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

	m_type = SECURE_NONE;
	m_ctx = NULL;
	m_ssl = NULL;
	m_bHTML = false;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: CSMTPMail
// DESCRIPTION: Destructor of CSMTPMail class.
//   ARGUMENTS: none
// USES GLOBAL: m_RecvBuf, m_SendBuf
// MODIFIES GL: m_RecvBuf, m_SendBuf
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
CSMTPMail::~CSMTPMail()
{
	if(m_bConnected) DisconnectRemoteServer();

	if(m_SendBuf)
	{
		delete[] m_SendBuf;
		m_SendBuf = NULL;
	}
	if(m_RecvBuf)
	{
		delete[] m_RecvBuf;
		m_RecvBuf = NULL;
	}

	CleanupOpenSSL();
	WSACleanup();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddAttachment
// DESCRIPTION: New attachment is added.
//   ARGUMENTS: const char *Path - name of attachment added
// USES GLOBAL: Attachments
// MODIFIES GL: Attachments
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::AddAttachment(const char *Path)
{
	Attachments.insert(Attachments.end(),Path);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddRecipient
// DESCRIPTION: New recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the recipient
//              const char *name - name of the recipient
// USES GLOBAL: Recipients
// MODIFIES GL: Recipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::AddRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	recipient.Mail.insert(0,email);
	name!=NULL ? recipient.Name.insert(0,name) : recipient.Name.insert(0,"");

	Recipients.insert(Recipients.end(), recipient);   
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddCCRecipient
// DESCRIPTION: New cc-recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the cc-recipient
//              const char *name - name of the ccc-recipient
// USES GLOBAL: CCRecipients
// MODIFIES GL: CCRecipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::AddCCRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	recipient.Mail.insert(0,email);
	name!=NULL ? recipient.Name.insert(0,name) : recipient.Name.insert(0,"");

	CCRecipients.insert(CCRecipients.end(), recipient);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddBCCRecipient
// DESCRIPTION: New bcc-recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the bcc-recipient
//              const char *name - name of the bccc-recipient
// USES GLOBAL: BCCRecipients
// MODIFIES GL: BCCRecipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::AddBCCRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	recipient.Mail.insert(0,email);
	name!=NULL ? recipient.Name.insert(0,name) : recipient.Name.insert(0,"");

	BCCRecipients.insert(BCCRecipients.end(), recipient);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddMsgLine
// DESCRIPTION: Adds new line in a message.
//   ARGUMENTS: const char *Text - text of the new line
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::AddMsgLine(const char* Text)
{
	MsgBody.insert(MsgBody.end(),Text);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelMsgLine
// DESCRIPTION: Deletes specified line in text message.. .
//   ARGUMENTS: unsigned int Line - line to be delete
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DelMsgLine(unsigned int Line)
{
	if(Line > MsgBody.size())
		throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);
	MsgBody.erase(MsgBody.begin()+Line);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelRecipients
// DESCRIPTION: Deletes all recipients. .
//   ARGUMENTS: void
// USES GLOBAL: Recipients
// MODIFIES GL: Recipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DelRecipients()
{
	Recipients.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelBCCRecipients
// DESCRIPTION: Deletes all BCC recipients. .
//   ARGUMENTS: void
// USES GLOBAL: BCCRecipients
// MODIFIES GL: BCCRecipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DelBCCRecipients()
{
	BCCRecipients.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelCCRecipients
// DESCRIPTION: Deletes all CC recipients. .
//   ARGUMENTS: void
// USES GLOBAL: CCRecipients
// MODIFIES GL: CCRecipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DelCCRecipients()
{
	CCRecipients.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelMsgLines
// DESCRIPTION: Deletes message text.
//   ARGUMENTS: void
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DelMsgLines()
{
	MsgBody.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelAttachments
// DESCRIPTION: Deletes all recipients. .
//   ARGUMENTS: void
// USES GLOBAL: Attchments
// MODIFIES GL: Attachments
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DelAttachments()
{
	Attachments.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddBCCRecipient
// DESCRIPTION: New bcc-recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the bcc-recipient
//              const char *name - name of the bccc-recipient
// USES GLOBAL: BCCRecipients
// MODIFIES GL: BCCRecipients, m_oError
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::ModMsgLine(unsigned int Line,const char* Text)
{
	if(Text)
	{
		if(Line > MsgBody.size())
			throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);
		MsgBody.at(Line) = string(Text);
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: Send
// DESCRIPTION: Sending the mail. .
//   ARGUMENTS: none
// USES GLOBAL: m_sSMTPSrvName, m_iSMTPSrvPort, m_SendBuf, m_RecvBuf, m_sLogin,
//              m_sPassword, m_sMailFrom, Recipients, CCRecipients,
//              BCCRecipients, m_sMsgBody, Attachments, 
// MODIFIES GL: m_SendBuf 
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
bool CSMTPMail::Send()
{
	unsigned int i,rcpt_count,res,FileId;
	char *FileBuf = NULL, *FileName = NULL;
	FILE* hFile = NULL;
	unsigned long int FileSize,TotalSize,MsgPart;

	// ***** CONNECTING TO SMTP SERVER *****

	// connecting to remote host if not already connected:
	if(hSocket==NULL)
	{
		if(!ConnectRemoteServer(m_sSMTPSrvName.c_str(), m_iSMTPSrvPort, m_type, m_bAuthenticate))
			throw ECSmtp(ECSmtp::WSA_INVALID_SOCKET);
	}

	try{
		// ***** SENDING E-MAIL *****
		
		// MAIL <SP> FROM:<reverse-path> <CRLF>
		if(!m_sMailFrom.size())
			throw ECSmtp(ECSmtp::UNDEF_MAIL_FROM);
		Command_Entry* pEntry = FindCommandEntry(command_MAILFROM);
		sprintf_s(m_SendBuf, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", m_sMailFrom.c_str());
		SendData(pEntry);
		ReceiveResponse(pEntry);

		// RCPT <SP> TO:<forward-path> <CRLF>
		if(!(rcpt_count = Recipients.size()))
			throw ECSmtp(ECSmtp::UNDEF_RECIPIENTS);
		pEntry = FindCommandEntry(command_RCPTTO);
		for(i=0;i<Recipients.size();i++)
		{
			sprintf_s(m_SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (Recipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		for(i=0;i<CCRecipients.size();i++)
		{
			sprintf_s(m_SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (CCRecipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		for(i=0;i<BCCRecipients.size();i++)
		{
			sprintf_s(m_SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (BCCRecipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}
		
		pEntry = FindCommandEntry(command_DATA);
		// DATA <CRLF>
		strcpy_s(m_SendBuf, BUFFER_SIZE, "DATA\r\n");
		SendData(pEntry);
		ReceiveResponse(pEntry);
		
		pEntry = FindCommandEntry(command_DATABLOCK);
		// send header(s)
		FormatHeader(m_SendBuf);
		SendData(pEntry);

		// send text message
		if(GetMsgLines())
		{
			for(i=0;i<GetMsgLines();i++)
			{
				sprintf_s(m_SendBuf, BUFFER_SIZE,"%s\r\n",GetMsgLineText(i));
				SendData(pEntry);
			}
		}
		else
		{
			sprintf_s(m_SendBuf, BUFFER_SIZE,"%s\r\n"," ");
			SendData(pEntry);
		}

		// next goes attachments (if they are)
		if((FileBuf = new char[55]) == NULL)
			throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

		if((FileName = new char[255]) == NULL)
			throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

		TotalSize = 0;
		for(FileId=0;FileId<Attachments.size();FileId++)
		{
			strcpy_s(FileName,BUFFER_SIZE,Attachments[FileId].c_str());

			sprintf_s(m_SendBuf, BUFFER_SIZE,"--%s\r\n",BOUNDARY_TEXT);
			strcat_s(m_SendBuf,BUFFER_SIZE,"Content-Type: application/x-msdownload; name=\"");
			strcat_s(m_SendBuf,BUFFER_SIZE,&FileName[Attachments[FileId].find_last_of("\\") + 1]);
			strcat_s(m_SendBuf,BUFFER_SIZE,"\"\r\n");
			strcat_s(m_SendBuf,BUFFER_SIZE,"Content-Transfer-Encoding: base64\r\n");
			strcat_s(m_SendBuf,BUFFER_SIZE,"Content-Disposition: attachment; filename=\"");
			strcat_s(m_SendBuf,BUFFER_SIZE,&FileName[Attachments[FileId].find_last_of("\\") + 1]);
			strcat_s(m_SendBuf,BUFFER_SIZE,"\"\r\n");
			strcat_s(m_SendBuf,BUFFER_SIZE,"\r\n");

			SendData(pEntry);

			// opening the file:
			errno_t err = fopen_s(&hFile, FileName,"rb");
			if(hFile == NULL)
				throw ECSmtp(ECSmtp::FILE_NOT_EXIST);
			
			// checking file size:
			FileSize = 0;
			while(!feof(hFile))
				FileSize += fread(FileBuf,sizeof(char),54,hFile);
			TotalSize += FileSize;

			// sending the file:
			if(TotalSize/1024 > MSG_SIZE_IN_MB*1024)
				throw ECSmtp(ECSmtp::MSG_TOO_BIG);
			else
			{
				fseek (hFile,0,SEEK_SET);

				MsgPart = 0;
				for(i=0;i<FileSize/54+1;i++)
				{
					res = fread(FileBuf,sizeof(char),54,hFile);
					MsgPart ? strcat(m_SendBuf,m_cry.GetEncodeString(reinterpret_cast<const unsigned char*>(FileBuf),res).c_str())
							  :strcpy(m_SendBuf,m_cry.GetEncodeString(reinterpret_cast<const unsigned char*>(FileBuf),res).c_str());
					strcat_s(m_SendBuf,BUFFER_SIZE,"\r\n");
					MsgPart += res + 2;
					if(MsgPart >= BUFFER_SIZE/2)
					{ // sending part of the message
						MsgPart = 0;
						SendData(pEntry); // FileBuf, FileName, fclose(hFile);
					}
				}
				if(MsgPart)
				{
					SendData(pEntry); // FileBuf, FileName, fclose(hFile);
				}
			}
			fclose(hFile);
		}
		delete[] FileBuf;
		delete[] FileName;
		
		// sending last message block (if there is one or more attachments)
		if(Attachments.size())
		{
			sprintf_s(m_SendBuf, BUFFER_SIZE,"\r\n--%s--\r\n",BOUNDARY_TEXT);
			SendData(pEntry);
		}
		
		pEntry = FindCommandEntry(command_DATAEND);
		// <CRLF> . <CRLF>
		strcpy_s(m_SendBuf, BUFFER_SIZE,"\r\n.\r\n");
		SendData(pEntry);
		ReceiveResponse(pEntry);
	}
	catch(const ECSmtp&)
	{
		DisconnectRemoteServer();
		return false;
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: ConnectRemoteServer
// DESCRIPTION: Connecting to the service running on the remote server. 
//   ARGUMENTS: const char *server - service name
//              const unsigned short port - service port
// USES GLOBAL: m_pcSMTPSrvName, m_iSMTPSrvPort, m_SendBuf, m_RecvBuf, m_pcLogin,
//              m_pcPassword, m_pcMailFrom, Recipients, CCRecipients,
//              BCCRecipients, m_pcMsgBody, Attachments, 
// MODIFIES GL: m_oError 
//     RETURNS: socket of the remote service
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
bool CSMTPMail::ConnectRemoteServer(const char *szServer, const unsigned short nPort_, 
								SMTP_SECURE securityType/*=DO_NOT_SET*/,
								bool authenticate/*=true*/, const char *login/*=NULL*/,
								const char *password/*=NULL*/)
{
	unsigned short nPort = 0;
	LPSERVENT lpServEnt;
	SOCKADDR_IN sockAddr;
	unsigned long ul = 1;
	fd_set fdwrite,fdexcept;
	timeval timeout;
	int res = 0;
	bool conected=false;

	try
	{
		timeout.tv_sec = TIME_IN_SEC;
		timeout.tv_usec = 0;

		hSocket = INVALID_SOCKET;

		if((hSocket = socket(PF_INET, SOCK_STREAM,0)) == INVALID_SOCKET)
			throw ECSmtp(ECSmtp::WSA_INVALID_SOCKET);

		if(nPort_ != 0)
			nPort = htons(nPort_);
		else
		{
			lpServEnt = getservbyname("mail", 0);
			if (lpServEnt == NULL)
				nPort = htons(25);
			else 
				nPort = lpServEnt->s_port;
		}
				
		sockAddr.sin_family = AF_INET;
		sockAddr.sin_port = nPort;
		if((sockAddr.sin_addr.s_addr = inet_addr(szServer)) == INADDR_NONE)
		{
			LPHOSTENT host;
				
			host = gethostbyname(szServer);

			char pHostIP[100];
			sprintf_s(pHostIP, sizeof(pHostIP),"%d.%d.%d.%d\0", *(unsigned char*)(host->h_addr_list[0])
				, *(unsigned char*)(host->h_addr_list[0]+1)
				, *(unsigned char*)(host->h_addr_list[0]+2)
				, *(unsigned char*)(host->h_addr_list[0]+3));

			if (host)
				memcpy(&sockAddr.sin_addr,host->h_addr_list[0],host->h_length);
			else
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_GETHOSTBY_NAME_ADDR);
			}				
		}

		// start non-blocking mode for socket:

		if(ioctlsocket(hSocket,FIONBIO, (unsigned long*)&ul) == SOCKET_ERROR)
		{

			closesocket(hSocket);
			throw ECSmtp(ECSmtp::WSA_IOCTLSOCKET);
		}

		if(connect(hSocket,(LPSOCKADDR)&sockAddr,sizeof(sockAddr)) == SOCKET_ERROR)
		{
			if(WSAGetLastError() != WSAEWOULDBLOCK)
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_CONNECT);
			}
		}
		else
			return true;

		while(true)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdexcept);

			FD_SET(hSocket,&fdwrite);
			FD_SET(hSocket,&fdexcept);

			if((res = select(hSocket+1,NULL,&fdwrite,&fdexcept,&timeout)) == SOCKET_ERROR)
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}

			if(!res)
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::SELECT_TIMEOUT);
			}
			if(res && FD_ISSET(hSocket,&fdwrite))
				break;
			if(res && FD_ISSET(hSocket,&fdexcept))
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}
		}

		FD_CLR(hSocket,&fdwrite);
		FD_CLR(hSocket,&fdexcept);

		if(securityType!=DO_NOT_SET) SetSecurityType(securityType);
		if(GetSecurityType() == SECURE_TLS || GetSecurityType() == SECURE_SSL)
		{
			InitOpenSSL();
			if(GetSecurityType() == SECURE_SSL)
			{
				OpenSSLConnect();
			}
		}

		Command_Entry* pEntry = FindCommandEntry(command_INIT);
		ReceiveResponse(pEntry);

		SayHello();

		if(GetSecurityType() == SECURE_TLS)
		{
			StartTls();
			SayHello();
		}

		if(authenticate && IsKeywordSupported(m_RecvBuf, "AUTH") == true)
		{
			if(login) SetLogin(login);
			if(!m_sLogin.size())
				throw ECSmtp(ECSmtp::UNDEF_LOGIN);

			if(password) SetPassword(password);
			if(!m_sPassword.size())
				throw ECSmtp(ECSmtp::UNDEF_PASSWORD);

			if(IsKeywordSupported(m_RecvBuf, "LOGIN") == true)
			{
				pEntry = FindCommandEntry(command_AUTHLOGIN);
				strcpy_s(m_SendBuf,BUFFER_SIZE, "AUTH LOGIN\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				// send login:
				string encoded_login = m_cry.GetEncodeString(reinterpret_cast<const unsigned char*>(m_sLogin.c_str()),m_sLogin.size());
				pEntry = FindCommandEntry(command_USER);
				sprintf_s(m_SendBuf,BUFFER_SIZE,"%s\r\n",encoded_login.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
				
				// send password:
				string encoded_password = m_cry.GetEncodeString(reinterpret_cast<const unsigned char*>(m_sPassword.c_str()),m_sPassword.size());
				pEntry = FindCommandEntry(command_PASSWORD);
				sprintf_s(m_SendBuf,BUFFER_SIZE,"%s\r\n",encoded_password.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if(IsKeywordSupported(m_RecvBuf, "PLAIN") == true)
			{
				pEntry = FindCommandEntry(command_AUTHPLAIN);
				sprintf_s(m_SendBuf,BUFFER_SIZE, "^%s^%s", m_sLogin.c_str(), m_sPassword.c_str());
				for(unsigned int i=0; i<strlen(m_SendBuf); i++)
				{
					if(m_SendBuf[i]=='^') m_SendBuf[i]='\0';
				}
				const unsigned char *ustrLogin = CharToUnsignedChar(m_SendBuf);
				string encoded_login = m_cry.GetEncodeString(ustrLogin, strlen(m_SendBuf));
				delete[] ustrLogin;
				sprintf_s(m_SendBuf, BUFFER_SIZE,"AUTH PLAIN %s", encoded_login.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if(IsKeywordSupported(m_RecvBuf, "CRAM-MD5") == true)
			{
				pEntry = FindCommandEntry(command_AUTHCRAMMD5);
				strcpy_s(m_SendBuf,BUFFER_SIZE, "AUTH CRAM-MD5\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				string encoded_challenge = m_RecvBuf;
				encoded_challenge = encoded_challenge.substr(4);
				string decoded_challenge = m_cry.GetDecodeString(encoded_challenge);
				
				/////////////////////////////////////////////////////////////////////
				//test data from RFC 2195
				//decoded_challenge = "<1896.697170952@postoffice.reston.mci.net>";
				//m_sLogin = "tim";
				//m_sPassword = "tanstaaftanstaaf";
				//MD5 should produce b913a602c7eda7a495b4e6e7334d3890
				//should encode as dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
				/////////////////////////////////////////////////////////////////////

				unsigned char *ustrChallenge = CharToUnsignedChar(decoded_challenge.c_str());
				unsigned char *ustrPassword = CharToUnsignedChar(m_sPassword.c_str());
				if(!ustrChallenge || !ustrPassword)
					throw ECSmtp(ECSmtp::BAD_LOGIN_PASSWORD);

				// if ustrPassword is longer than 64 bytes reset it to ustrPassword=MD5(ustrPassword)
				int passwordLength=m_sPassword.size();
				if(passwordLength > 64){
					MD5 md5password;
					md5password.update(ustrPassword, passwordLength);
					md5password.finalize();
					ustrPassword = md5password.raw_digest();
					passwordLength = 16;
				}

				//Storing ustrPassword in pads
				unsigned char ipad[65], opad[65];
				memset(ipad, 0, 64);
				memset(opad, 0, 64);
				memcpy(ipad, ustrPassword, passwordLength);
				memcpy(opad, ustrPassword, passwordLength);

				// XOR ustrPassword with ipad and opad values
				for(int i=0; i<64; i++){
					ipad[i] ^= 0x36;
					opad[i] ^= 0x5c;
				}

				//perform inner MD5
				MD5 md5pass1;
				md5pass1.update(ipad, 64);
				md5pass1.update(ustrChallenge, decoded_challenge.size());
				md5pass1.finalize();
				unsigned char *ustrResult = md5pass1.raw_digest();

				//perform outer MD5
				MD5 md5pass2;
				md5pass2.update(opad, 64);
				md5pass2.update(ustrResult, 16);
				md5pass2.finalize();
				decoded_challenge = md5pass2.hex_digest();

				delete[] ustrChallenge;
				delete[] ustrPassword;
				delete[] ustrResult;

				decoded_challenge = m_sLogin + " " + decoded_challenge;
				encoded_challenge = m_cry.GetEncodeString(reinterpret_cast<const unsigned char*>(decoded_challenge.c_str()),decoded_challenge.size());

				sprintf_s(m_SendBuf, BUFFER_SIZE,"%s\r\n", encoded_challenge.c_str());
				pEntry = FindCommandEntry(command_PASSWORD);
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if(IsKeywordSupported(m_RecvBuf, "DIGEST-MD5") == true)
			{
				pEntry = FindCommandEntry(command_DIGESTMD5);
				strcpy_s(m_SendBuf, BUFFER_SIZE,"AUTH DIGEST-MD5\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				string encoded_challenge = m_RecvBuf;
				encoded_challenge = encoded_challenge.substr(4);
				string decoded_challenge = m_cry.GetDecodeString(encoded_challenge);

				/////////////////////////////////////////////////////////////////////
				//Test data from RFC 2831
				//To test jump into authenticate and read this line and the ones down to next test data section
				//decoded_challenge = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
				/////////////////////////////////////////////////////////////////////
				
				//Get the nonce (manditory)
				int find = decoded_challenge.find("nonce");
				if(find<0)
					throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);
				string nonce = decoded_challenge.substr(find+7);
				find = nonce.find("\"");
				if(find<0)
					throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);
				nonce = nonce.substr(0, find);

				//Get the realm (optional)
				string realm;
				find = decoded_challenge.find("realm");
				if(find>=0){
					realm = decoded_challenge.substr(find+7);
					find = realm.find("\"");
					if(find<0)
						throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);
					realm = realm.substr(0, find);
				}

				//Create a cnonce
				char cnonce[17], nc[9];
				sprintf_s(cnonce, sizeof(cnonce),"%x", time(NULL));

				//Set nonce count
				sprintf_s(nc, sizeof(nc), "%08d", 1);

				//Set QOP
				string qop = "auth";

				//Get server address and set uri
				//Skip this step during test
				int len;
				struct sockaddr_storage addr;
				len = sizeof addr;
				if(!getpeername(hSocket, (struct sockaddr*)&addr, &len))
					throw ECSmtp(ECSmtp::BAD_SERVER_NAME);

				struct sockaddr_in *s = (struct sockaddr_in *)&addr;
				string uri =inet_ntoa(s->sin_addr);
				uri = "smtp/" + uri;

				/////////////////////////////////////////////////////////////////////
				//test data from RFC 2831
				//m_sLogin = "chris";
				//m_sPassword = "secret";
				//strcpy_s(cnonce, "OA6MHXh6VqTrRk");
				//uri = "imap/elwood.innosoft.com";
				//Should form the response:
				//    charset=utf-8,username="chris",
				//    realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",nc=00000001,
				//    cnonce="OA6MHXh6VqTrRk",digest-uri="imap/elwood.innosoft.com",
				//    response=d388dad90d4bbd760a152321f2143af7,qop=auth
				//This encodes to:
				//    Y2hhcnNldD11dGYtOCx1c2VybmFtZT0iY2hyaXMiLHJlYWxtPSJlbHdvb2
				//    QuaW5ub3NvZnQuY29tIixub25jZT0iT0E2TUc5dEVRR20yaGgiLG5jPTAw
				//    MDAwMDAxLGNub25jZT0iT0E2TUhYaDZWcVRyUmsiLGRpZ2VzdC11cmk9Im
				//    ltYXAvZWx3b29kLmlubm9zb2Z0LmNvbSIscmVzcG9uc2U9ZDM4OGRhZDkw
				//    ZDRiYmQ3NjBhMTUyMzIxZjIxNDNhZjcscW9wPWF1dGg=
				/////////////////////////////////////////////////////////////////////

				//Calculate digest response
				unsigned char *ustrRealm = CharToUnsignedChar(realm.c_str());
				unsigned char *ustrUsername = CharToUnsignedChar(m_sLogin.c_str());
				unsigned char *ustrPassword = CharToUnsignedChar(m_sPassword.c_str());
				unsigned char *ustrNonce = CharToUnsignedChar(nonce.c_str());
				unsigned char *ustrCNonce = CharToUnsignedChar(cnonce);
				unsigned char *ustrUri = CharToUnsignedChar(uri.c_str());
				unsigned char *ustrNc = CharToUnsignedChar(nc);
				unsigned char *ustrQop = CharToUnsignedChar(qop.c_str());
				if(!ustrRealm || !ustrUsername || !ustrPassword || !ustrNonce || !ustrCNonce || !ustrUri || !ustrNc || !ustrQop)
					throw ECSmtp(ECSmtp::BAD_LOGIN_PASSWORD);

				MD5 md5a1a;
				md5a1a.update(ustrUsername, m_sLogin.size());
				md5a1a.update((unsigned char*)":", 1);
				md5a1a.update(ustrRealm, realm.size());
				md5a1a.update((unsigned char*)":", 1);
				md5a1a.update(ustrPassword, m_sPassword.size());
				md5a1a.finalize();
				unsigned char *ua1 = md5a1a.raw_digest();

				MD5 md5a1b;
				md5a1b.update(ua1, 16);
				md5a1b.update((unsigned char*)":", 1);
				md5a1b.update(ustrNonce, nonce.size());
				md5a1b.update((unsigned char*)":", 1);
				md5a1b.update(ustrCNonce, strlen(cnonce));
				//authzid could be added here
				md5a1b.finalize();
				char *a1 = md5a1b.hex_digest();
				
				MD5 md5a2;
				md5a2.update((unsigned char*) "AUTHENTICATE:", 13);
				md5a2.update(ustrUri, uri.size());
				//authint and authconf add an additional line here	
				md5a2.finalize();
				char *a2 = md5a2.hex_digest();

				delete[] ua1;
				ua1 = CharToUnsignedChar(a1);
				unsigned char *ua2 = CharToUnsignedChar(a2);
				
				//compute KD
				MD5 md5;
				md5.update(ua1, 32);
				md5.update((unsigned char*)":", 1);
				md5.update(ustrNonce, nonce.size());
				md5.update((unsigned char*)":", 1);
				md5.update(ustrNc, strlen(nc));
				md5.update((unsigned char*)":", 1);
				md5.update(ustrCNonce, strlen(cnonce));
				md5.update((unsigned char*)":", 1);
				md5.update(ustrQop, qop.size());
				md5.update((unsigned char*)":", 1);
				md5.update(ua2, 32);
				md5.finalize();
				decoded_challenge = md5.hex_digest();

				delete[] ustrRealm;
				delete[] ustrUsername;
				delete[] ustrPassword;
				delete[] ustrNonce;
				delete[] ustrCNonce;
				delete[] ustrUri;
				delete[] ustrNc;
				delete[] ustrQop;
				delete[] ua1;
				delete[] ua2;
				delete[] a1;
				delete[] a2;

				//send the response
				if(strstr(m_RecvBuf, "charset")>=0) 
					sprintf_s(m_SendBuf, BUFFER_SIZE,"charset=utf-8,username=\"%s\"", m_sLogin.c_str());
				else 
					sprintf_s(m_SendBuf, BUFFER_SIZE,"username=\"%s\"", m_sLogin.c_str());

				if(!realm.empty())
				{
					sprintf_s(m_RecvBuf, BUFFER_SIZE,",realm=\"%s\"", realm.c_str());
					strcat_s(m_SendBuf,BUFFER_SIZE, m_RecvBuf);
				}
				sprintf_s(m_RecvBuf, BUFFER_SIZE,",nonce=\"%s\"", nonce.c_str());
				strcat_s(m_SendBuf, BUFFER_SIZE,m_RecvBuf);
				sprintf_s(m_RecvBuf, BUFFER_SIZE,",nc=%s", nc);
				strcat_s(m_SendBuf, BUFFER_SIZE,m_RecvBuf);
				sprintf_s(m_RecvBuf, BUFFER_SIZE,",cnonce=\"%s\"", cnonce);
				strcat_s(m_SendBuf,BUFFER_SIZE, m_RecvBuf);
				sprintf_s(m_RecvBuf, BUFFER_SIZE,",digest-uri=\"%s\"", uri.c_str());
				strcat_s(m_SendBuf, BUFFER_SIZE,m_RecvBuf);
				sprintf_s(m_RecvBuf, BUFFER_SIZE,",response=%s", decoded_challenge.c_str());
				strcat_s(m_SendBuf, BUFFER_SIZE,m_RecvBuf);
				sprintf_s(m_RecvBuf, BUFFER_SIZE,",qop=%s", qop.c_str());
				strcat_s(m_SendBuf,BUFFER_SIZE, m_RecvBuf);
				unsigned char *ustrDigest = CharToUnsignedChar(m_SendBuf);
				encoded_challenge = m_cry.GetEncodeString(ustrDigest, strlen(m_SendBuf));
				delete[] ustrDigest;
				sprintf_s(m_SendBuf, BUFFER_SIZE,"%s\r\n", encoded_challenge.c_str());
				pEntry = FindCommandEntry(command_DIGESTMD5);
				SendData(pEntry);
				ReceiveResponse(pEntry);

				//Send completion carraige return
				sprintf_s(m_SendBuf, BUFFER_SIZE,"\r\n");				
				pEntry = FindCommandEntry(command_PASSWORD);
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else throw ECSmtp(ECSmtp::LOGIN_NOT_SUPPORTED);
		}
	}
	catch(const ECSmtp&)
	{
		if(m_RecvBuf[0]=='5' && m_RecvBuf[1]=='3' && m_RecvBuf[2]=='0')
			m_bConnected=false;
		DisconnectRemoteServer();
		throw;
		return false;
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DisconnectRemoteServer
// DESCRIPTION: Disconnects from the SMTP server and closes the socket
//   ARGUMENTS: none
// USES GLOBAL: none
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: David Johns
// AUTHOR/DATE: DRJ 2010-08-14
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::DisconnectRemoteServer()
{
	if(m_bConnected) SayQuit();
	if(hSocket)
	{
		closesocket(hSocket);
	}
	hSocket = NULL;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SmtpXYZdigits
// DESCRIPTION: Converts three letters from m_RecvBuf to the number.
//   ARGUMENTS: none
// USES GLOBAL: m_RecvBuf
// MODIFIES GL: none
//     RETURNS: integer number
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
int CSMTPMail::SmtpXYZdigits()
{
	if(m_RecvBuf == NULL)
		return 0;
	return (m_RecvBuf[0]-'0')*100 + (m_RecvBuf[1]-'0')*10 + m_RecvBuf[2]-'0';
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: FormatHeader
// DESCRIPTION: Prepares a header of the message.
//   ARGUMENTS: char* header - formated header string
// USES GLOBAL: Recipients, CCRecipients, BCCRecipients
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::FormatHeader(char* header)
{
	char month[][4] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
	size_t i;
	string to;
	string cc;
	string bcc;

	SYSTEMTIME hosttime;
	GetLocalTime(&hosttime);

	// check for at least one recipient
	if(Recipients.size())
	{
		for (i=0;i<Recipients.size();i++)
		{
			if(i > 0)
				to.append(",");
			to += Recipients[i].Name;
			to.append("<");
			to += Recipients[i].Mail;
			to.append(">");
		}
	}
	else
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENTS);

	if(CCRecipients.size())
	{
		for (i=0;i<CCRecipients.size();i++)
		{
			if(i > 0)
				cc. append(",");
			cc += CCRecipients[i].Name;
			cc.append("<");
			cc += CCRecipients[i].Mail;
			cc.append(">");
		}
	}

	if(BCCRecipients.size())
	{
		for (i=0;i<BCCRecipients.size();i++)
		{
			if(i > 0)
				bcc.append(",");
			bcc += BCCRecipients[i].Name;
			bcc.append("<");
			bcc += BCCRecipients[i].Mail;
			bcc.append(">");
		}
	}
	
	// Date: <SP> <dd> <SP> <mon> <SP> <yy> <SP> <hh> ":" <mm> ":" <ss> <SP> <zone> <CRLF>
	sprintf_s(header,BUFFER_SIZE,"Date: %d %s %d %d:%d:%d\r\n",	
				hosttime.wDay,
				month[hosttime.wMonth-1],
				hosttime.wYear,
				hosttime.wHour,
				hosttime.wMinute,
				hosttime.wSecond); 
	
	// From: <SP> <sender>  <SP> "<" <sender-email> ">" <CRLF>
	if(!m_sMailFrom.size())
		throw ECSmtp(ECSmtp::UNDEF_MAIL_FROM);
	strcat_s(header,BUFFER_SIZE,"From: ");
	if(m_sNameFrom.size())
		strcat_s(header, BUFFER_SIZE,m_sNameFrom.c_str());
	strcat_s(header,BUFFER_SIZE," <");
	if(m_sNameFrom.size())
		strcat_s(header,BUFFER_SIZE,m_sMailFrom.c_str());
	else
		strcat_s(header,BUFFER_SIZE,"mail@domain.com");
	strcat_s(header, BUFFER_SIZE,">\r\n");

	// X-Mailer: <SP> <xmailer-app> <CRLF>
	if(m_sXMailer.size())
	{
		strcat_s(header,BUFFER_SIZE,"X-Mailer: ");
		strcat_s(header,BUFFER_SIZE, m_sXMailer.c_str());
		strcat_s(header, BUFFER_SIZE,"\r\n");
	}

	// Reply-To: <SP> <reverse-path> <CRLF>
	if(m_sReplyTo.size())
	{
		strcat_s(header,BUFFER_SIZE, "Reply-To: ");
		strcat_s(header, BUFFER_SIZE,m_sReplyTo.c_str());
		strcat_s(header, BUFFER_SIZE,"\r\n");
	}

	// X-Priority: <SP> <number> <CRLF>
	switch(m_iXPriority)
	{
		case XPRIORITY_HIGH:
			strcat_s(header,BUFFER_SIZE,"X-Priority: 2 (High)\r\n");
			break;
		case XPRIORITY_NORMAL:
			strcat_s(header,BUFFER_SIZE,"X-Priority: 3 (Normal)\r\n");
			break;
		case XPRIORITY_LOW:
			strcat_s(header,BUFFER_SIZE,"X-Priority: 4 (Low)\r\n");
			break;
		default:
			strcat_s(header,BUFFER_SIZE,"X-Priority: 3 (Normal)\r\n");
	}

	// To: <SP> <remote-user-mail> <CRLF>
	strcat_s(header,BUFFER_SIZE,"To: ");
	strcat_s(header, BUFFER_SIZE,to.c_str());
	strcat_s(header, BUFFER_SIZE,"\r\n");

	// Cc: <SP> <remote-user-mail> <CRLF>
	if(CCRecipients.size())
	{
		strcat_s(header,BUFFER_SIZE,"Cc: ");
		strcat_s(header,BUFFER_SIZE, cc.c_str());
		strcat_s(header, BUFFER_SIZE,"\r\n");
	}

	if(BCCRecipients.size())
	{
		strcat_s(header,BUFFER_SIZE,"Bcc: ");
		strcat_s(header,BUFFER_SIZE, bcc.c_str());
		strcat_s(header, BUFFER_SIZE,"\r\n");
	}

	// Subject: <SP> <subject-text> <CRLF>
	if(!m_sSubject.size()) 
		strcat_s(header, BUFFER_SIZE,"Subject:  ");
	else
	{
	  strcat_s(header,BUFFER_SIZE, "Subject: ");
	  strcat_s(header, BUFFER_SIZE,m_sSubject.c_str());
	}
	strcat_s(header, BUFFER_SIZE,"\r\n");
	
	// MIME-Version: <SP> 1.0 <CRLF>
	strcat_s(header,BUFFER_SIZE,"MIME-Version: 1.0\r\n");
	if(!Attachments.size())
	{ // no attachments
		if(m_bHTML) 
			strcat_s(header,BUFFER_SIZE,"Content-Type: text/html; charset=\"US-ASCII\"\r\n");
		else 
			strcat_s(header,BUFFER_SIZE,"Content-type: text/plain; charset=\"US-ASCII\"\r\n");
		strcat_s(header,BUFFER_SIZE,"Content-Transfer-Encoding: 7bit\r\n");
		strcat_s(m_SendBuf,BUFFER_SIZE,"\r\n");
	}
	else
	{ // there is one or more attachments
		strcat_s(header,BUFFER_SIZE,"Content-Type: multipart/mixed; boundary=\"");
		strcat_s(header,BUFFER_SIZE,BOUNDARY_TEXT);
		strcat_s(header,BUFFER_SIZE,"\"\r\n");
		strcat_s(header,BUFFER_SIZE,"\r\n");
		// first goes text message
		strcat_s(m_SendBuf,BUFFER_SIZE,"--");
		strcat_s(m_SendBuf,BUFFER_SIZE,BOUNDARY_TEXT);
		strcat_s(m_SendBuf,BUFFER_SIZE,"\r\n");
		if(m_bHTML) 
			strcat_s(m_SendBuf,BUFFER_SIZE,"Content-type: text/html; charset=US-ASCII\r\n");
		else 
			strcat_s(m_SendBuf,BUFFER_SIZE,"Content-type: text/plain; charset=US-ASCII\r\n");
		strcat_s(m_SendBuf,BUFFER_SIZE,"Content-Transfer-Encoding: 7bit\r\n");
		strcat_s(m_SendBuf,BUFFER_SIZE,"\r\n");
	}

	// done
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: ReceiveData
// DESCRIPTION: Receives a row terminated '\n'.
//   ARGUMENTS: none
// USES GLOBAL: m_RecvBuf
// MODIFIES GL: m_RecvBuf
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-07
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// MODIFICATION: Receives data as much as possible. Another function ReceiveResponse
//               will ensure the received data contains '\n'
// AUTHOR/DATE:  John Tang 2010-08-01
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::ReceiveData(Command_Entry* pEntry)
{
	if(m_ssl != NULL)
	{
		ReceiveData_SSL(m_ssl, pEntry);
		return;
	}
	int res = 0;
	fd_set fdread;
	timeval time;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	if(m_RecvBuf == NULL)
		throw ECSmtp(ECSmtp::RECVBUF_IS_EMPTY);

	FD_ZERO(&fdread);

	FD_SET(hSocket,&fdread);

	if((res = select(hSocket+1, &fdread, NULL, NULL, &time)) == SOCKET_ERROR)
	{
		FD_CLR(hSocket,&fdread);
		throw ECSmtp(ECSmtp::WSA_SELECT);
	}

	if(!res)
	{
		//timeout
		FD_CLR(hSocket,&fdread);
		throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
	}

	if(FD_ISSET(hSocket,&fdread))
	{
		res = recv(hSocket,m_RecvBuf,BUFFER_SIZE,0);
		if(res == SOCKET_ERROR)
		{
			FD_CLR(hSocket,&fdread);
			throw ECSmtp(ECSmtp::WSA_RECV);
		}
	}

	FD_CLR(hSocket,&fdread);
	m_RecvBuf[res] = 0;
	if(res == 0)
	{
		throw ECSmtp(ECSmtp::CONNECTION_CLOSED);
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SendData
// DESCRIPTION: Sends data from m_SendBuf buffer.
//   ARGUMENTS: none
// USES GLOBAL: m_SendBuf
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SendData(Command_Entry* pEntry)
{
	if(m_ssl != NULL)
	{
		SendData_SSL(m_ssl, pEntry);
		return;
	}
	int idx = 0,res,nLeft = strlen(m_SendBuf);
	fd_set fdwrite;
	timeval time;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	if(m_SendBuf == NULL)
		throw ECSmtp(ECSmtp::SENDBUF_IS_EMPTY);

	while(nLeft > 0)
	{
		FD_ZERO(&fdwrite);

		FD_SET(hSocket,&fdwrite);

		if((res = select(hSocket+1,NULL,&fdwrite,NULL,&time)) == SOCKET_ERROR)
		{
			FD_CLR(hSocket,&fdwrite);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_CLR(hSocket,&fdwrite);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if(res && FD_ISSET(hSocket,&fdwrite))
		{
			res = send(hSocket,&m_SendBuf[idx],nLeft,0);
			if(res == SOCKET_ERROR || res == 0)
			{
				FD_CLR(hSocket,&fdwrite);
				throw ECSmtp(ECSmtp::WSA_SEND);
			}
			nLeft -= res;
			idx += res;
		}
	}

	FD_CLR(hSocket,&fdwrite);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetLocalHostName
// DESCRIPTION: Returns local host name. 
//   ARGUMENTS: none
// USES GLOBAL: m_pcLocalHostName
// MODIFIES GL: m_oError, m_pcLocalHostName 
//     RETURNS: socket of the remote service
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
const char* CSMTPMail::GetLocalHostName()
{
	return m_sLocalHostName.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetRecipientCount
// DESCRIPTION: Returns the number of recipents.
//   ARGUMENTS: none
// USES GLOBAL: Recipients
// MODIFIES GL: none 
//     RETURNS: number of recipents
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
unsigned int CSMTPMail::GetRecipientCount() const
{
	return Recipients.size();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetBCCRecipientCount
// DESCRIPTION: Returns the number of bcc-recipents. 
//   ARGUMENTS: none
// USES GLOBAL: BCCRecipients
// MODIFIES GL: none 
//     RETURNS: number of bcc-recipents
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
unsigned int CSMTPMail::GetBCCRecipientCount() const
{
	return BCCRecipients.size();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetCCRecipientCount
// DESCRIPTION: Returns the number of cc-recipents.
//   ARGUMENTS: none
// USES GLOBAL: CCRecipients
// MODIFIES GL: none 
//     RETURNS: number of cc-recipents
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
unsigned int CSMTPMail::GetCCRecipientCount() const
{
	return CCRecipients.size();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetReplyTo
// DESCRIPTION: Returns m_pcReplyTo string.
//   ARGUMENTS: none
// USES GLOBAL: m_sReplyTo
// MODIFIES GL: none 
//     RETURNS: m_sReplyTo string
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
const char* CSMTPMail::GetReplyTo() const
{
	return m_sReplyTo.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetMailFrom
// DESCRIPTION: Returns m_pcMailFrom string.
//   ARGUMENTS: none
// USES GLOBAL: m_sMailFrom
// MODIFIES GL: none 
//     RETURNS: m_sMailFrom string
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
const char* CSMTPMail::GetMailFrom() const
{
	return m_sMailFrom.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetSenderName
// DESCRIPTION: Returns m_pcNameFrom string.
//   ARGUMENTS: none
// USES GLOBAL: m_sNameFrom
// MODIFIES GL: none 
//     RETURNS: m_sNameFrom string
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
const char* CSMTPMail::GetSenderName() const
{
	return m_sNameFrom.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetSubject
// DESCRIPTION: Returns m_pcSubject string.
//   ARGUMENTS: none
// USES GLOBAL: m_sSubject
// MODIFIES GL: none 
//     RETURNS: m_sSubject string
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
const char* CSMTPMail::GetSubject() const
{
	return m_sSubject.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetXMailer
// DESCRIPTION: Returns m_pcXMailer string.
//   ARGUMENTS: none
// USES GLOBAL: m_pcXMailer
// MODIFIES GL: none 
//     RETURNS: m_pcXMailer string
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
const char* CSMTPMail::GetXMailer() const
{
	return m_sXMailer.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetXPriority
// DESCRIPTION: Returns m_iXPriority string.
//   ARGUMENTS: none
// USES GLOBAL: m_iXPriority
// MODIFIES GL: none 
//     RETURNS: CSmptXPriority m_pcXMailer
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
CSmptXPriority CSMTPMail::GetXPriority() const
{
	return m_iXPriority;
}

const char* CSMTPMail::GetMsgLineText(unsigned int Line) const
{
	if(Line > MsgBody.size())
		throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);
	return MsgBody.at(Line).c_str();
}

unsigned int CSMTPMail::GetMsgLines() const
{
	return MsgBody.size();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetXPriority
// DESCRIPTION: Setting priority of the message.
//   ARGUMENTS: CSmptXPriority priority - priority of the message (	XPRIORITY_HIGH,
//              XPRIORITY_NORMAL, XPRIORITY_LOW)
// USES GLOBAL: none
// MODIFIES GL: m_iXPriority 
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetXPriority(CSmptXPriority priority)
{
	m_iXPriority = priority;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetReplyTo
// DESCRIPTION: Setting the return address.
//   ARGUMENTS: const char *ReplyTo - return address
// USES GLOBAL: m_sReplyTo
// MODIFIES GL: m_sReplyTo
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetReplyTo(const char *ReplyTo)
{
	m_sReplyTo.erase();
	m_sReplyTo.insert(0,ReplyTo);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSenderMail
// DESCRIPTION: Setting sender's mail.
//   ARGUMENTS: const char *EMail - sender's e-mail
// USES GLOBAL: m_sMailFrom
// MODIFIES GL: m_sMailFrom
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetSenderMail(const char *EMail)
{
	m_sMailFrom.erase();
	m_sMailFrom.insert(0,EMail);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSenderName
// DESCRIPTION: Setting sender's name.
//   ARGUMENTS: const char *Name - sender's name
// USES GLOBAL: m_sNameFrom
// MODIFIES GL: m_sNameFrom
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetSenderName(const char *Name)
{
	m_sNameFrom.erase();
	m_sNameFrom.insert(0,Name);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSubject
// DESCRIPTION: Setting subject of the message.
//   ARGUMENTS: const char *Subject - subject of the message
// USES GLOBAL: m_sSubject
// MODIFIES GL: m_sSubject
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetSubject(const char *Subject)
{
	m_sSubject.erase();
	m_sSubject.insert(0,Subject);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSubject
// DESCRIPTION: Setting the name of program which is sending the mail.
//   ARGUMENTS: const char *XMailer - programe name
// USES GLOBAL: m_sXMailer
// MODIFIES GL: m_sXMailer
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetXMailer(const char *XMailer)
{
	m_sXMailer.erase();
	m_sXMailer.insert(0,XMailer);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetLogin
// DESCRIPTION: Setting the login of SMTP account's owner.
//   ARGUMENTS: const char *Login - login of SMTP account's owner
// USES GLOBAL: m_sLogin
// MODIFIES GL: m_sLogin
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetLogin(const char *Login)
{
	m_sLogin.erase();
	m_sLogin.insert(0,Login);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetPassword
// DESCRIPTION: Setting the password of SMTP account's owner.
//   ARGUMENTS: const char *Password - password of SMTP account's owner
// USES GLOBAL: m_sPassword
// MODIFIES GL: m_sPassword
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JP 2010-07-08
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetPassword(const char *Password)
{
	m_sPassword.erase();
	m_sPassword.insert(0,Password);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSMTPServer
// DESCRIPTION: Setting the SMTP service name and port.
//   ARGUMENTS: const char* SrvName - SMTP service name
//              const unsigned short SrvPort - SMTO service port
// USES GLOBAL: m_sSMTPSrvName
// MODIFIES GL: m_sSMTPSrvName 
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
//							JO 2010-0708
////////////////////////////////////////////////////////////////////////////////
void CSMTPMail::SetSMTPServer(const char* SrvName, const unsigned short SrvPort, bool authenticate)
{
	m_iSMTPSrvPort = SrvPort;
	m_sSMTPSrvName.erase();
	m_sSMTPSrvName.insert(0, SrvName);
	m_bAuthenticate = authenticate;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetErrorText (friend function)
// DESCRIPTION: Returns the string for specified error code.
//   ARGUMENTS: CSmtpError ErrorId - error code
// USES GLOBAL: none
// MODIFIES GL: none 
//     RETURNS: error string
//      AUTHOR: Jakub Piwowarczyk
// AUTHOR/DATE: JP 2010-01-28
////////////////////////////////////////////////////////////////////////////////
string ECSmtp::GetErrorText() const
{
	switch(ErrorCode)
	{
		case ECSmtp::CSMTP_NO_ERROR:
			return "";
		case ECSmtp::WSA_STARTUP:
			return "Unable to initialise winsock2";
		case ECSmtp::WSA_VER:
			return "Wrong version of the winsock2";
		case ECSmtp::WSA_SEND:
			return "Function send() failed";
		case ECSmtp::WSA_RECV:
			return "Function recv() failed";
		case ECSmtp::WSA_CONNECT:
			return "Function connect failed";
		case ECSmtp::WSA_GETHOSTBY_NAME_ADDR:
			return "Unable to determine remote server";
		case ECSmtp::WSA_INVALID_SOCKET:
			return "Invalid winsock2 socket";
		case ECSmtp::WSA_HOSTNAME:
			return "Function hostname() failed";
		case ECSmtp::WSA_IOCTLSOCKET:
			return "Function ioctlsocket() failed";
		case ECSmtp::BAD_IPV4_ADDR:
			return "Improper IPv4 address";
		case ECSmtp::UNDEF_MSG_HEADER:
			return "Undefined message header";
		case ECSmtp::UNDEF_MAIL_FROM:
			return "Undefined mail sender";
		case ECSmtp::UNDEF_SUBJECT:
			return "Undefined message subject";
		case ECSmtp::UNDEF_RECIPIENTS:
			return "Undefined at least one reciepent";
		case ECSmtp::UNDEF_RECIPIENT_MAIL:
			return "Undefined recipent mail";
		case ECSmtp::UNDEF_LOGIN:
			return "Undefined user login";
		case ECSmtp::UNDEF_PASSWORD:
			return "Undefined user password";
		case ECSmtp::BAD_LOGIN_PASSWORD:
			return "Invalid user login or password";
		case ECSmtp::BAD_DIGEST_RESPONSE:
			return "Server returned a bad digest MD5 response";
		case ECSmtp::BAD_SERVER_NAME:
			return "Unable to determine server name for digest MD5 response";
		case ECSmtp::COMMAND_MAIL_FROM:
			return "Server returned error after sending MAIL FROM";
		case ECSmtp::COMMAND_EHLO:
			return "Server returned error after sending EHLO";
		case ECSmtp::COMMAND_AUTH_PLAIN:
			return "Server returned error after sending AUTH PLAIN";
		case ECSmtp::COMMAND_AUTH_LOGIN:
			return "Server returned error after sending AUTH LOGIN";
		case ECSmtp::COMMAND_AUTH_CRAMMD5:
			return "Server returned error after sending AUTH CRAM-MD5";
		case ECSmtp::COMMAND_AUTH_DIGESTMD5:
			return "Server returned error after sending AUTH DIGEST-MD5";
		case ECSmtp::COMMAND_DIGESTMD5:
			return "Server returned error after sending MD5 DIGEST";
		case ECSmtp::COMMAND_DATA:
			return "Server returned error after sending DATA";
		case ECSmtp::COMMAND_QUIT:
			return "Server returned error after sending QUIT";
		case ECSmtp::COMMAND_RCPT_TO:
			return "Server returned error after sending RCPT TO";
		case ECSmtp::MSG_BODY_ERROR:
			return "Error in message body";
		case ECSmtp::CONNECTION_CLOSED:
			return "Server has closed the connection";
		case ECSmtp::SERVER_NOT_READY:
			return "Server is not ready";
		case ECSmtp::SERVER_NOT_RESPONDING:
			return "Server not responding";
		case ECSmtp::FILE_NOT_EXIST:
			return "File not exist";
		case ECSmtp::MSG_TOO_BIG:
			return "Message is too big";
		case ECSmtp::BAD_LOGIN_PASS:
			return "Bad login or password";
		case ECSmtp::UNDEF_XYZ_RESPONSE:
			return "Undefined xyz SMTP response";
		case ECSmtp::LACK_OF_MEMORY:
			return "Lack of memory";
		case ECSmtp::TIME_ERROR:
			return "time() error";
		case ECSmtp::RECVBUF_IS_EMPTY:
			return "RecvBuf is empty";
		case ECSmtp::SENDBUF_IS_EMPTY:
			return "SendBuf is empty";
		case ECSmtp::OUT_OF_MSG_RANGE:
			return "Specified line number is out of message size";
		case ECSmtp::COMMAND_EHLO_STARTTLS:
			return "Server returned error after sending STARTTLS";
		case ECSmtp::SSL_PROBLEM:
			return "SSL problem";
		case ECSmtp::COMMAND_DATABLOCK:
			return "Failed to send data block";
		case ECSmtp::STARTTLS_NOT_SUPPORTED:
			return "The STARTTLS command is not supported by the server";
		case ECSmtp::LOGIN_NOT_SUPPORTED:
			return "AUTH LOGIN is not supported by the server";
		default:
			return "Undefined error id";
	}
}

void CSMTPMail::SayHello()
{
	Command_Entry* pEntry = FindCommandEntry(command_EHLO);
	sprintf_s(m_SendBuf, BUFFER_SIZE,"EHLO %s\r\n", GetLocalHostName()!=NULL ? m_sLocalHostName.c_str() : "domain");
	SendData(pEntry);
	ReceiveResponse(pEntry);
	m_bConnected=true;
}

void CSMTPMail::SayQuit()
{
	// ***** CLOSING CONNECTION *****
	
	Command_Entry* pEntry = FindCommandEntry(command_QUIT);
	// QUIT <CRLF>
	strcpy_s(m_SendBuf, BUFFER_SIZE,"QUIT\r\n");
	SendData(pEntry);
	ReceiveResponse(pEntry);
	m_bConnected=false;
}

void CSMTPMail::StartTls()
{
	if(IsKeywordSupported(m_RecvBuf, "STARTTLS") == false)
	{
		throw ECSmtp(ECSmtp::STARTTLS_NOT_SUPPORTED);
	}
	Command_Entry* pEntry = FindCommandEntry(command_STARTTLS);
	strcpy_s(m_SendBuf,BUFFER_SIZE, "STARTTLS\r\n");
	SendData(pEntry);
	ReceiveResponse(pEntry);

	OpenSSLConnect();
}

void CSMTPMail::ReceiveData_SSL(SSL* ssl, Command_Entry* pEntry)
{
	int res = 0;
	int offset = 0;
	fd_set fdread;
	fd_set fdwrite;
	timeval time;

	int read_blocked_on_write = 0;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	if(m_RecvBuf == NULL)
		throw ECSmtp(ECSmtp::RECVBUF_IS_EMPTY);

	bool bFinish = false;

	while(!bFinish)
	{
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		FD_SET(hSocket,&fdread);

		if(read_blocked_on_write)
		{
			FD_SET(hSocket, &fdwrite);
		}

		if((res = select(hSocket+1, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if(FD_ISSET(hSocket,&fdread) || (read_blocked_on_write && FD_ISSET(hSocket,&fdwrite)) )
		{
			while(1)
			{
				read_blocked_on_write=0;

				const int buff_len = 1024;
				char buff[buff_len];

				res = SSL_read(ssl, buff, buff_len);

				int ssl_err = SSL_get_error(ssl, res);
				if(ssl_err == SSL_ERROR_NONE)
				{
					if(offset + res > BUFFER_SIZE - 1)
					{
						FD_ZERO(&fdread);
						FD_ZERO(&fdwrite);
						throw ECSmtp(ECSmtp::LACK_OF_MEMORY);
					}
					memcpy(m_RecvBuf + offset, buff, res);
					offset += res;
					if(SSL_pending(ssl))
					{
						continue;
					}
					else
					{
						bFinish = true;
						break;
					}
				}
				else if(ssl_err == SSL_ERROR_ZERO_RETURN)
				{
					bFinish = true;
					break;
				}
				else if(ssl_err == SSL_ERROR_WANT_READ)
				{
					break;
				}
				else if(ssl_err == SSL_ERROR_WANT_WRITE)
				{
					/* We get a WANT_WRITE if we're
					trying to rehandshake and we block on
					a write during that rehandshake.

					We need to wait on the socket to be 
					writeable but reinitiate the read
					when it is */
					read_blocked_on_write=1;
					break;
				}
				else
				{
					FD_ZERO(&fdread);
					FD_ZERO(&fdwrite);
					throw ECSmtp(ECSmtp::SSL_PROBLEM);
				}
			}
		}
	}

	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	m_RecvBuf[offset] = 0;
	if(offset == 0)
	{
		throw ECSmtp(ECSmtp::CONNECTION_CLOSED);
	}
}

void CSMTPMail::ReceiveResponse(Command_Entry* pEntry)
{
	string line;
	int reply_code = 0;
	bool bFinish = false;
	while(!bFinish)
	{
		ReceiveData(pEntry);
		line.append(m_RecvBuf);
		size_t len = line.length();
		size_t begin = 0;
		size_t offset = 0;

		while(1) // loop for all lines
		{
			while(offset + 1 < len)
			{
				if(line[offset] == '\r' && line[offset+1] == '\n')
					break;
				++offset;
			}
			if(offset + 1 < len) // we found a line
			{
				// see if this is the last line
				// the last line must match the pattern: XYZ<SP>*<CRLF> or XYZ<CRLF> where XYZ is a string of 3 digits 
				offset += 2; // skip <CRLF>
				if(offset - begin >= 5)
				{
					if(isdigit(line[begin]) && isdigit(line[begin+1]) && isdigit(line[begin+2]))
					{
						// this is the last line
						if(offset - begin == 5 || line[begin+3] == ' ')
						{
							reply_code = (line[begin]-'0')*100 + (line[begin+1]-'0')*10 + line[begin+2]-'0';
							bFinish = true;
							break;
						}
					}
				}
				begin = offset;	// try to find next line
			}
			else // we haven't received the last line, so we need to receive more data 
			{
				break;
			}
		}
	}
	strcpy_s(m_RecvBuf,BUFFER_SIZE, line.c_str());
	if(reply_code != pEntry->valid_reply_code)
	{
		throw ECSmtp(pEntry->error);
	}
}

void CSMTPMail::SendData_SSL(SSL* ssl, Command_Entry* pEntry)
{
	int offset = 0,res,nLeft = strlen(m_SendBuf);
	fd_set fdwrite;
	fd_set fdread;
	timeval time;

	int write_blocked_on_read = 0;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	if(m_SendBuf == NULL)
		throw ECSmtp(ECSmtp::SENDBUF_IS_EMPTY);

	while(nLeft > 0)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		FD_SET(hSocket,&fdwrite);

		if(write_blocked_on_read)
		{
			FD_SET(hSocket, &fdread);
		}

		if((res = select(hSocket+1,&fdread,&fdwrite,NULL,&time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if(FD_ISSET(hSocket,&fdwrite) || (write_blocked_on_read && FD_ISSET(hSocket, &fdread)) )
		{
			write_blocked_on_read=0;

			/* Try to write */
			res = SSL_write(ssl, m_SendBuf+offset, nLeft);
	          
			switch(SSL_get_error(ssl,res))
			{
			  /* We wrote something*/
			  case SSL_ERROR_NONE:
				nLeft -= res;
				offset += res;
				break;
	              
				/* We would have blocked */
			  case SSL_ERROR_WANT_WRITE:
				break;

				/* We get a WANT_READ if we're
				   trying to rehandshake and we block on
				   write during the current connection.
	               
				   We need to wait on the socket to be readable
				   but reinitiate our write when it is */
			  case SSL_ERROR_WANT_READ:
				write_blocked_on_read=1;
				break;
	              
				  /* Some other error */
			  default:	      
				FD_ZERO(&fdread);
				FD_ZERO(&fdwrite);
				throw ECSmtp(ECSmtp::SSL_PROBLEM);
			}

		}
	}

	FD_ZERO(&fdwrite);
	FD_ZERO(&fdread);
}

void CSMTPMail::InitOpenSSL()
{
	SSL_library_init();
	SSL_load_error_strings();
	m_ctx = SSL_CTX_new (SSLv23_client_method());
	if(m_ctx == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);
}

void CSMTPMail::OpenSSLConnect()
{
	if(m_ctx == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);
	m_ssl = SSL_new (m_ctx);   
	if(m_ssl == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);
	SSL_set_fd (m_ssl, (int)hSocket);
    SSL_set_mode(m_ssl, SSL_MODE_AUTO_RETRY);

	int res = 0;
	fd_set fdwrite;
	fd_set fdread;
	int write_blocked = 0;
	int read_blocked = 0;

	timeval time;
	time.tv_sec = TIME_IN_SEC;
	time.tv_usec = 0;

	while(1)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		if(write_blocked)
			FD_SET(hSocket, &fdwrite);
		if(read_blocked)
			FD_SET(hSocket, &fdread);

		if(write_blocked || read_blocked)
		{
			write_blocked = 0;
			read_blocked = 0;
			if((res = select(hSocket+1,&fdread,&fdwrite,NULL,&time)) == SOCKET_ERROR)
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}
			if(!res)
			{
				//timeout
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
			}
		}
		res = SSL_connect(m_ssl);
		switch(SSL_get_error(m_ssl, res))
		{
		  case SSL_ERROR_NONE:
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			return;
			break;
              
		  case SSL_ERROR_WANT_WRITE:
			write_blocked = 1;
			break;

		  case SSL_ERROR_WANT_READ:
			read_blocked = 1;
			break;
              
		  default:	      
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::SSL_PROBLEM);
		}
	}
}

void CSMTPMail::CleanupOpenSSL()
{
	if(m_ssl != NULL)
	{
		SSL_shutdown (m_ssl);  /* send SSL/TLS close_notify */
		SSL_free (m_ssl);
		m_ssl = NULL;
	}
	if(m_ctx != NULL)
	{
		SSL_CTX_free (m_ctx);	
		m_ctx = NULL;
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}
}


Command_Entry* CSMTPMail::FindCommandEntry(SMTP_COMMAND command)
{
	Command_Entry* pEntry = NULL;
	for(int i = 0; i < sizeof(command_list)/sizeof(command_list[0]); ++i)
	{
		if(command_list[i].command == command)
		{
			pEntry = &command_list[i];
			break;
		}
	}

	return pEntry;
}

bool CSMTPMail::IsKeywordSupported(const char* response, const char* keyword)
{
	if(response == NULL || keyword == NULL)
		return false;
	int res_len = strlen(response);
	int key_len = strlen(keyword);
	if(res_len < key_len)
		return false;
	int pos = 0;
	for(; pos < res_len - key_len + 1; ++pos)
	{
		if(_strnicmp(keyword, response+pos, key_len) == 0)
		{
			if(pos > 0 &&
				(response[pos - 1] == '-' ||
				response[pos - 1] == ' ' ||
				response[pos - 1] == '='))
			{
				if(pos+key_len < res_len)
				{
					if(response[pos+key_len] == ' ' ||
						response[pos+key_len] == '=')
					{
						return true;
					}
					else if(pos+key_len+1 < res_len)
					{
						if(response[pos+key_len] == '\r' &&
							response[pos+key_len+1] == '\n')
						{
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}

unsigned char* CSMTPMail::CharToUnsignedChar(const char *strIn)
{
	unsigned char *strOut;
	unsigned long length,i;
	length = strlen(strIn);
	strOut = new unsigned char[length+1];
	if(!strOut) return NULL;
	for(i=0; i<length; i++) strOut[i] = (unsigned char) strIn[i];
	strOut[length]='\0';
	return strOut;
}

CString CSMTPMail::GetEventString(EVENTTYPE eventType)
{
	int nIdx = 0 , nCount = m_vcEventSeverity.size();
	for (nIdx=0 ; nIdx < nCount; nIdx++)
	{
		if (m_vcEventSeverity[nIdx].event_type == eventType)
		{
			return CString(m_vcEventSeverity[nIdx].event_name.c_str());
		}
	}
	return _T("");
}