#pragma once

struct PTZAuthenticate
{
	wstring		strIP;
	wstring		strUserName;
	wstring		strPassword;
	int			nPort;
	PTZ_ACTION	ptzAction;
	int			ptzPresetPoint;

	PTZAuthenticate(){};
	PTZAuthenticate(wstring	wsIP,wstring wsUserName,wstring wsPassword,int iPort,PTZ_ACTION ptzAct,int ptzPPoint)
	{
		strIP = wsIP;
		strUserName = wsUserName;
		strPassword = wsPassword;
		nPort = iPort;
		ptzAction = ptzAct;
		ptzPresetPoint = ptzPPoint;
	}
};

class CPTZAction
{
public:
	CPTZAction(void);
	~CPTZAction(void);

private:
	PTZAuthenticate	m_ptzAuthenticate;

private:
	void GetCGIString(const PTZAuthenticate& ptzAuthenticate, char* chValue);
	void GetAuthEncode(const PTZAuthenticate& ptzAuthenticate, char* chValue);
	void GetIPAddress(const PTZAuthenticate& ptzAuthenticate, char* chValue);
	void FormatSendMsg(const char* chCGIString, const char* chIPString, const char* chAuthString, char* chValue);
	bool CheckICMP(char* chIP);

public:
	void SetPTZAuthenticate(const PTZAuthenticate& ptzAuthenticate){m_ptzAuthenticate = ptzAuthenticate;};
	bool Action();
};
