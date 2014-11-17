#include "StdAfx.h"
#include "EventMgrAction.h"
#include "DataCeneter.h"
#include "Crypto.h"

struct ActionLog
{
	SYSTEMTIME hosttime;
	ec_Event_Action event_action;
	EventInfo eventInfo;
	bool isActionSuccess;
};

queue<ActionLog> g_vcActionLog;
queue<EventInfo> g_vcEventInfo;
HANDLE g_handle = NULL;
HANDLE g_handle_log = NULL;
bool g_EventAction = false;
bool g_RefreshData = false;
CString g_ExecuteFolder = _T("");

unsigned __stdcall exacute_event_action(void* pArguments);
unsigned __stdcall write_event_action_log(void* pArguments);

#define EVENT_FOLDER				_T("\\Event") 
#define ETROVISION_FOLDER			_T("\\Etrovision") 
#define SNAPSHOT_FOLDER				_T("%s\\Etrovision\\Event") 
#define LOG_FOLDER					_T("\\log") 
#define LOG_FILE_NAME				"\\log\\%d%d%d.log" 

unsigned __stdcall exacute_event_action(void* pArguments)
{
	USES_CONVERSION;
	CEventMgrAction *pthis = (CEventMgrAction*)pArguments;
	EventInfo eventInfo;
	map<CString, vector<ec_Event_Action> >::iterator it;
	map<CString, vector<ec_Event_Action> > mapEventAction;
	vector<ec_Event_Action> vcEventAction;
	ActionLog acLog;
	int nIdx = 0, nCount = 0;
	CString cstr;

	while(g_EventAction)
	{
		if(g_RefreshData)
		{
			pthis->GetEventAction(mapEventAction);
			g_RefreshData = false;
		}

		if (g_vcEventInfo.size())
		{
			bool isActionSuccess = false;

			eventInfo = g_vcEventInfo.front(); 

			EnterCriticalSection(&pthis->m_criSec);
			g_vcEventInfo.pop();
			LeaveCriticalSection(&pthis->m_criSec);

			cstr.Format(_T("%s"),eventInfo.tcMAC);
			it = mapEventAction.find(cstr.MakeUpper()); 
			if (it != mapEventAction.end())
			{
				vcEventAction.clear();
				vcEventAction = pthis->FilterActionByEventType((EVENTTYPE)eventInfo.nEventType, it->second);
				nCount = (int)vcEventAction.size();

				for (nIdx = 0; nIdx < nCount; nIdx++)
				{
					switch(vcEventAction[nIdx].action_type)
					{
					case ACTION_RECORDING:
						{
							isActionSuccess = pthis->StartRecording(vcEventAction[nIdx]);
						}
						break;
					case ACTION_PTZ:
						{
							isActionSuccess = pthis->OperatePTZ(vcEventAction[nIdx]);
						}
						break;
					case ACTION_SNAPSHOT:
						{
							isActionSuccess = pthis->SnapShot(vcEventAction[nIdx]);
						}
						break;
					case ACTION_EMAIL:
						{
							isActionSuccess = pthis->SendEmail(eventInfo, vcEventAction[nIdx]);
						}
						break;
					case ACTION_PLAYSOUND:
						{
							isActionSuccess = pthis->PlaySound(vcEventAction[nIdx]);
						}
						break;
					case ACTION_CUSTOM:
						{
							isActionSuccess = pthis->ExacuteFile(vcEventAction[nIdx]);
						}
						break;
					}

					SYSTEMTIME hosttime;
					GetLocalTime(&hosttime);
					acLog.event_action = vcEventAction[nIdx];
					acLog.eventInfo = eventInfo;
					acLog.hosttime = hosttime;
					acLog.isActionSuccess = isActionSuccess;
					EnterCriticalSection(&pthis->m_criSec);
					g_vcActionLog.push(acLog);
					LeaveCriticalSection(&pthis->m_criSec);
				}
			}
		}
		Sleep(500);
	}
	return 0;
}

unsigned __stdcall write_event_action_log(void* pArguments)
{
	USES_CONVERSION;
	CEventMgrAction *pthis = (CEventMgrAction*)pArguments;
	ActionLog acLog;
	char strLogFileName[1024] = {0};
	char strFileContent[100] = {0};
	string str;
	int nLength = 0;
	CString strFile;
	strFile.Format(_T("%s%s"),g_ExecuteFolder,A2W(LOG_FILE_NAME));

	while(g_EventAction)
	{
		if (g_vcActionLog.size())
		{
			acLog = g_vcActionLog.front();

			EnterCriticalSection(&pthis->m_criSec);
			g_vcActionLog.pop();
			LeaveCriticalSection(&pthis->m_criSec);

			SYSTEMTIME hosttime;
			GetLocalTime(&hosttime);
			sprintf_s(strLogFileName, sizeof(strLogFileName), W2A(strFile),hosttime.wYear,hosttime.wMonth,hosttime.wDay);

			FILE *pFile = NULL;

			if(fopen_s(&pFile, strLogFileName, "a+") == 0)
			{
				if (acLog.isActionSuccess)
					str = "success";
				else
					str = "fail";

				nLength = sprintf_s(strFileContent, sizeof(strFileContent),"%d/%d/%d %02d:%02d:%02d do action:%s %s.\n",
									acLog.hosttime.wYear,acLog.hosttime.wMonth,acLog.hosttime.wDay,
									acLog.hosttime.wHour,acLog.hosttime.wMinute,acLog.hosttime.wSecond,
									pthis->GetActionName(acLog.event_action.action_type).c_str(),str.c_str());

				fwrite(strFileContent, nLength , 1, pFile);  

			}
			fclose( pFile );
		}
		Sleep(500);
	}
	return 0;
}

CEventMgrAction::CEventMgrAction(void):m_pDataCenter(NULL)
{
	InitializeCriticalSection (&m_criSec);

	USES_CONVERSION;
	wchar_t buffer[125];
	GetModuleFileName(NULL,buffer,125);
	int pos = wstring( buffer ).find_last_of( _T("\\/") );
	wstring str = wstring( buffer ).substr( 0, pos);
	g_ExecuteFolder.Format(_T("%s"),str.c_str());

	Initial();
}

CEventMgrAction::~CEventMgrAction(void)
{
	CloseEventAction();

	g_EventAction = false;
	if (g_handle)
	{
		WaitForSingleObject( g_handle, INFINITE );
		CloseHandle(g_handle);
		g_handle = NULL;
	}

	if (g_handle_log)
	{
		WaitForSingleObject( g_handle_log, INFINITE );
		CloseHandle(g_handle_log);
		g_handle_log = NULL;
	}

	if (m_pDataCenter)
	{
		delete m_pDataCenter;
		m_pDataCenter = NULL;
	}

	DeleteCriticalSection(&m_criSec);
}

void CEventMgrAction::Initial()
{
	m_pDataCenter = new CDataCeneter;
	RefreshData();
	GetSnapshotFolder();
	CreateLogFolder();
	m_pDataCenter->QueryFromDC(REG_TBL, GET_ALL_EVENT, (LPVOID)&m_vcEventSeverity);

	g_EventAction = true;
	g_handle = (HANDLE)::_beginthreadex(NULL, 0, exacute_event_action, (LPVOID)this, 0, NULL);
	g_handle_log = (HANDLE)::_beginthreadex(NULL, 0, write_event_action_log, (LPVOID)this, 0, NULL);

	/*const DWORD MAXBUFFER(2048);
	TCHAR    chMsg[MAXBUFFER] ={0};
	HANDLE  hEventSource;
	LPTSTR  lpszStrings[1]={0};
	va_list pArg;
	va_start(pArg, _T("CEventMgrAction::Initial"));
	wvsprintfW(chMsg, _T("CEventMgrAction::Initial"), pArg);
	va_end(pArg);
	lpszStrings[0] = chMsg;

	hEventSource = RegisterEventSource(NULL,  _T("EventServer"));
	if (hEventSource != NULL)
	{
		ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCTSTR*) &lpszStrings[0], NULL);
		DeregisterEventSource(hEventSource);
	}*/
}

void CEventMgrAction::PushEventInfo(const EventInfo& eventInfo)
{
	EnterCriticalSection(&m_criSec);
	g_vcEventInfo.push(eventInfo);
	LeaveCriticalSection(&m_criSec);
}

void CEventMgrAction::RefreshAction()
{
	vector<ec_Event_Action> vcEventAction;
	map<CString, vector<ec_Event_Action> >::iterator it;

	if(!m_pDataCenter) return;
	vcEventAction.clear();
	m_pDataCenter->QueryFromDC(DATABASE, GET_EVENT_ACTION, (LPVOID)&vcEventAction);
	m_mapEventAction.clear();

	int nIdx = 0, nCount = (int)vcEventAction.size();
	for (int nIdx = 0; nIdx < nCount; nIdx++)
	{
		it = m_mapEventAction.find(vcEventAction[nIdx].source_device.mac_address.MakeUpper());
		if(it != m_mapEventAction.end())
			it->second.push_back(vcEventAction[nIdx]);
		else
		{
			vector<ec_Event_Action> vcAction;
			vcAction.push_back(vcEventAction[nIdx]);
			m_mapEventAction[vcEventAction[nIdx].source_device.mac_address.MakeUpper()] = vcAction;
		}
	}

}
void CEventMgrAction::RefreshData()
{
	//CloseEventAction();
	m_pDataCenter->QueryFromDC(FLUSH_DATA, NULL, NULL);
	RefreshAction();
	RefreshMailInfo();
	m_pDataCenter->QueryFromDC(DATABASE, GET_GROUP_CAM, (LPVOID)&m_vcGroupCam);

	g_RefreshData = true;
}

void CEventMgrAction::GetSnapshotFolder()
{
	CString buffer;
	//BOOL bRet = SHGetSpecialFolderPath(NULL, buffer.GetBuffer(MAX_PATH), CSIDL_COMMON_PICTURES,false);
	wstring wstr;
	m_pDataCenter->QueryFromDC(REG_TBL, GET_RECORD_PATH, (LPVOID)&wstr);
	buffer.Format(_T("%s"),wstr.c_str());

	CString str;
	str.Format(_T("%s%s"),buffer,EVENT_FOLDER);
	CFileFind cfFind;

	if ( !cfFind.FindFile(str) )
	{	
		CreateDirectory(str, NULL);
	}

	/*CString str;
	str.Format(_T("%s%s"),buffer,ETROVISION_FOLDER);
	CFileFind cfFind;

	if ( !cfFind.FindFile(str) )
	{	
		CreateDirectory(str, NULL);
	}

	str.Format(_T("%s%s%s"),buffer,ETROVISION_FOLDER,EVENT_FOLDER);
	if ( !cfFind.FindFile(str) )
	{	
		CreateDirectory(str, NULL);
	}*/

	m_strSnapshotFolder = str;
	buffer.ReleaseBuffer();
}

vector<ec_Event_Action> CEventMgrAction::FilterActionByEventType(EVENTTYPE eventType, const vector<ec_Event_Action>& vcAction)
{
	vector<ec_Event_Action> vcData;
	int nIdx = 0, nCount = vcAction.size();

	for (nIdx = 0; nIdx < nCount; nIdx++)
	{
		if (vcAction[nIdx].event_type == eventType)
		{
			vcData.push_back(vcAction[nIdx]);
		}
	}

	return vcData;
}

void CEventMgrAction::GetEventAction(map<CString, vector<ec_Event_Action> >& mapEventAction)
{ 
	mapEventAction = m_mapEventAction; 
}

void CEventMgrAction::RefreshMailInfo()
{
	USES_CONVERSION;

	if(!m_pDataCenter) return;
	m_pDataCenter->QueryFromDC(REG_TBL, GET_MAIL_SERVER, (LPVOID)&m_mailInfo);
	CCrypto cry(CRYPTO_WIN);
	
	string sDecrypt = W2A(m_mailInfo.SMTPPassword.c_str());
	sDecrypt = cry.GetDecodeString(sDecrypt);
	m_mailInfo.SMTPPassword = A2W(sDecrypt.c_str());
}

int CEventMgrAction::GetStreamID(int nCamID)
{
	int nIdx = 0, nCount = m_vcGroupCam.size();

	for (nIdx = 0; nIdx < nCount; nIdx++)
	{
		if (m_vcGroupCam[nIdx].cameraid == nCamID)
		{
			return m_vcGroupCam[nIdx].streamid;
		}
	}

	return 1;
}

void CEventMgrAction::CreateLogFolder()
{
	CFileFind cfFind;
	CString strFolder = g_ExecuteFolder+LOG_FOLDER;
	if ( !cfFind.FindFile(strFolder) )
	{	
		CreateDirectory(strFolder, NULL);
	}
}

string CEventMgrAction::GetActionName(EVENT_ACTION evAction)
{
	string actionName;
	switch(evAction)
	{
	case ACTION_RECORDING:
		actionName = "recording";
		break;
	case ACTION_PTZ:
		actionName = "do PTZ";
		break;
	case ACTION_SNAPSHOT:
		actionName = "snapshot";
		break;
	case ACTION_EMAIL:
		actionName = "send email";
		break;
	case ACTION_PLAYSOUND:
		actionName = "play sound";
		break;
	case ACTION_CUSTOM:
		actionName = "custom";
		break;
	}
	return actionName;
}