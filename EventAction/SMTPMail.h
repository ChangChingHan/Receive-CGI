#pragma once
#include "stdafx.h"
#include "openssl\ssl.h"
#include "Crypto.h"

#define TIME_IN_SEC		3*60		// how long client will wait for server response in non-blocking mode
#define BUFFER_SIZE 10240	  // SendData and RecvData buffers sizes
#define MSG_SIZE_IN_MB 5		// the maximum size of the message with all attachments
#define COUNTER_VALUE	100		// how many times program will try to receive data

const char BOUNDARY_TEXT[] = "__MESSAGE__ID__54yg6f6h6y456345";

enum CSmptXPriority
{
	XPRIORITY_HIGH = 2,
	XPRIORITY_NORMAL = 3,
	XPRIORITY_LOW = 4
};

class ECSmtp
{
public:
	enum CSmtpError
	{
		CSMTP_NO_ERROR = 0,
		WSA_STARTUP = 100, // WSAGetLastError()
		WSA_VER,
		WSA_SEND,
		WSA_RECV,
		WSA_CONNECT,
		WSA_GETHOSTBY_NAME_ADDR,
		WSA_INVALID_SOCKET,
		WSA_HOSTNAME,
		WSA_IOCTLSOCKET,
		WSA_SELECT,
		BAD_IPV4_ADDR,
		UNDEF_MSG_HEADER = 200,
		UNDEF_MAIL_FROM,
		UNDEF_SUBJECT,
		UNDEF_RECIPIENTS,
		UNDEF_LOGIN,
		UNDEF_PASSWORD,
		BAD_LOGIN_PASSWORD,
		BAD_DIGEST_RESPONSE,
		BAD_SERVER_NAME,
		UNDEF_RECIPIENT_MAIL,
		COMMAND_MAIL_FROM = 300,
		COMMAND_EHLO,
		COMMAND_AUTH_PLAIN,
		COMMAND_AUTH_LOGIN,
		COMMAND_AUTH_CRAMMD5,
		COMMAND_AUTH_DIGESTMD5,
		COMMAND_DIGESTMD5,
		COMMAND_DATA,
		COMMAND_QUIT,
		COMMAND_RCPT_TO,
		MSG_BODY_ERROR,
		CONNECTION_CLOSED = 400, // by server
		SERVER_NOT_READY, // remote server
		SERVER_NOT_RESPONDING,
		SELECT_TIMEOUT,
		FILE_NOT_EXIST,
		MSG_TOO_BIG,
		BAD_LOGIN_PASS,
		UNDEF_XYZ_RESPONSE,
		LACK_OF_MEMORY,
		TIME_ERROR,
		RECVBUF_IS_EMPTY,
		SENDBUF_IS_EMPTY,
		OUT_OF_MSG_RANGE,
		COMMAND_EHLO_STARTTLS,
		SSL_PROBLEM,
		COMMAND_DATABLOCK,
		STARTTLS_NOT_SUPPORTED,
		LOGIN_NOT_SUPPORTED
	};
	ECSmtp(CSmtpError err_) : ErrorCode(err_) {}
	CSmtpError GetErrorNum(void) const {return ErrorCode;}
	string GetErrorText(void) const;

private:
	CSmtpError ErrorCode;
};

enum SMTP_COMMAND
{
	command_INIT,
	command_EHLO,
	command_AUTHPLAIN,
	command_AUTHLOGIN,
	command_AUTHCRAMMD5,
	command_AUTHDIGESTMD5,
	command_DIGESTMD5,
	command_USER,
	command_PASSWORD,
	command_MAILFROM,
	command_RCPTTO,
	command_DATA,
	command_DATABLOCK,
	command_DATAEND,
	command_QUIT,
	command_STARTTLS
};

// TLS/SSL extension

typedef struct tagCommand_Entry
{
	SMTP_COMMAND       command;
	int                send_timeout;	 // 0 means no send is required
	int                recv_timeout;	 // 0 means no recv is required
	int                valid_reply_code; // 0 means no recv is required, so no reply code
	ECSmtp::CSmtpError error;
}Command_Entry;

class CSMTPMail
{
public:
	CSMTPMail(void);
	~CSMTPMail(void);

private:
	char *m_SendBuf;
	char *m_RecvBuf;
	struMail					m_SMTPInfo; 
	CString						m_EmailContent;
	CCrypto						m_cry;
	EventInfo					m_eventInfo;
	vector<strucEventSeverity>	m_vcEventSeverity;

public:
	void SetEventSeverity(vector<strucEventSeverity>& vcEventSeverity){m_vcEventSeverity = vcEventSeverity;};
	void SetSMTPInfo(const struMail& SMTPInfo){m_SMTPInfo = SMTPInfo;};
	void SetMailInfo(const EventInfo& eventInfo, const CString& strMailContent)
	{
		m_EmailContent = strMailContent;
		m_eventInfo = eventInfo;
	};
	bool SendMail();

	//////////////////////////////////////////////////////////////////////////

private:
	void AddRecipient(const char *email, const char *name=NULL);
	void AddBCCRecipient(const char *email, const char *name=NULL);
	void AddCCRecipient(const char *email, const char *name=NULL);    
	void AddAttachment(const char *path);   
	void AddMsgLine(const char* text);
	bool ConnectRemoteServer(const char* szServer, const unsigned short nPort_=0,
		SMTP_SECURE securityType=DO_NOT_SET,
		bool authenticate=true, const char *login=NULL,
		const char *password=NULL);
	void DisconnectRemoteServer();
	void DelRecipients(void);
	void DelBCCRecipients(void);
	void DelCCRecipients(void);
	void DelAttachments(void);
	void DelMsgLines(void);
	void DelMsgLine(unsigned int line);
	void ModMsgLine(unsigned int line,const char* text);
	unsigned int GetBCCRecipientCount() const;    
	unsigned int GetCCRecipientCount() const;
	unsigned int GetRecipientCount() const;    
	const char* GetLocalHostIP() const;
	const char* GetLocalHostName();
	const char* GetMsgLineText(unsigned int line) const;
	unsigned int GetMsgLines(void) const;
	const char* GetReplyTo() const;
	const char* GetMailFrom() const;
	const char* GetSenderName() const;
	const char* GetSubject() const;
	const char* GetXMailer() const;
	CSmptXPriority GetXPriority() const;
	bool Send();
	void SetSubject(const char*);
	void SetSenderName(const char*);
	void SetSenderMail(const char*);
	void SetReplyTo(const char*);
	void SetXMailer(const char*);
	void SetLogin(const char*);
	void SetPassword(const char*);
	void SetXPriority(CSmptXPriority);
	void SetSMTPServer(const char* server, const unsigned short port=0, bool authenticate=true);

	string m_sLocalHostName;
	string m_sMailFrom;
	string m_sNameFrom;
	string m_sSubject;
	string m_sXMailer;
	string m_sReplyTo;
	string m_sIPAddr;
	string m_sLogin;
	string m_sPassword;
	string m_sSMTPSrvName;
	unsigned short m_iSMTPSrvPort;
	bool m_bAuthenticate;
	CSmptXPriority m_iXPriority;

	SOCKET hSocket;
	bool m_bConnected;

	struct Recipient
	{
		string Name;
		string Mail;
	};

	vector<Recipient> Recipients;
	vector<Recipient> CCRecipients;
	vector<Recipient> BCCRecipients;
	vector<string> Attachments;
	vector<string> MsgBody;

	void ReceiveData(Command_Entry* pEntry);
	void SendData(Command_Entry* pEntry);
	void FormatHeader(char*);
	int SmtpXYZdigits();
	void SayHello();
	void SayQuit();

	// TLS/SSL extension

	SMTP_SECURE GetSecurityType() const
	{ return m_type; }
	void SetSecurityType(SMTP_SECURE type)
	{ m_type = type; }
	bool m_bHTML;
	SMTP_SECURE m_type;


	SSL_CTX*      m_ctx;
	SSL*          m_ssl;

	void ReceiveResponse(Command_Entry* pEntry);
	void InitOpenSSL();
	void OpenSSLConnect();
	void CleanupOpenSSL();
	void ReceiveData_SSL(SSL* ssl, Command_Entry* pEntry);
	void SendData_SSL(SSL* ssl, Command_Entry* pEntry);
	void StartTls();

	/*** Utility ***/
	Command_Entry* FindCommandEntry(SMTP_COMMAND command);
	bool IsKeywordSupported(const char* response, const char* keyword);
	unsigned char* CharToUnsignedChar(const char *strIn);
	CString GetEventString(EVENTTYPE eventType);
};
