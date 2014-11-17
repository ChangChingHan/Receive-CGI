#include "StdAfx.h"
#include "EventMgrAction.h"
#include "PTZAction.h"
#include "SMTPMail.h"
#include "Snapshot.h"
#include "DataCeneter.h"

#include "Wtsapi32.h"
#include "Userenv.h"
#include "Shlwapi.h"
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")

#define BUFSIZE					1024
HANDLE g_handle_sendeventaction = NULL;
bool g_sendeventaction = false;
queue<string> g_quAction;

unsigned __stdcall send_event_action_to_user(void* pArguments);
unsigned __stdcall send_event_action_to_user(void* pArguments)
{
	if (g_handle_sendeventaction)
	{
		HANDLE		hPipe = INVALID_HANDLE_VALUE;
		DWORD		len;
		DWORD		dwWritten;
		CEventMgrAction *pthis = (CEventMgrAction*)pArguments;

		if (WaitNamedPipe(ETRO_DO_EVENT_ACTION, NMPWAIT_WAIT_FOREVER) == 0)
		{
			g_handle_sendeventaction = NULL;
			return 0;
		}

		hPipe = CreateFile(
			ETRO_DO_EVENT_ACTION,
			GENERIC_WRITE,
			0,
			NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hPipe != INVALID_HANDLE_VALUE)
		{
			string str;
			while(g_sendeventaction)
			{
				if (g_quAction.size())
				{
					str = g_quAction.front();
					EnterCriticalSection(&pthis->m_criSec);
					g_quAction.pop();
					LeaveCriticalSection(&pthis->m_criSec);

					WriteFile(hPipe, str.c_str(), str.length(), &dwWritten, NULL);
					FlushFileBuffers(hPipe);
				}
				Sleep(500);
			}
		}
		CloseHandle(hPipe);
	}
	return 0;
}
bool CEventMgrAction::SendEmail(const EventInfo& eventInfo,const ec_Event_Action& EventAction)
{
	CSMTPMail mail;
	mail.SetMailInfo(eventInfo, EventAction.email_content.c_str());

	EnterCriticalSection(&m_criSec);
	mail.SetSMTPInfo(m_mailInfo);
	LeaveCriticalSection(&m_criSec);

	mail.SetEventSeverity(m_vcEventSeverity);
	return mail.SendMail();
	
}

bool CEventMgrAction::StartRecording(const ec_Event_Action& EventAction)
{
	bool bResult = true;

	bool bChckRecord = false;
	ec_Event_Action evAction = EventAction;
	int nStreamId = GetStreamID(evAction.target_device.cameraid);

	int nIdx = 0, nCount = evAction.target_device.vcStream.size();
	if (nCount >= nStreamId)
	{
		for (nIdx = 0; nIdx < nCount; nIdx++)
		{
			if (evAction.target_device.vcStream[nIdx].stream_type.Compare(_T("RE")) == 0)
			{
				bChckRecord = true;
				break;
			}
		}

		if(!bChckRecord)
		{
			evAction.target_device.vcStream[nStreamId-1].stream_type = _T("RE");
			m_pDataCenter->QueryFromDC(DATABASE, UPDATE_STREAM, (LPVOID)&evAction.target_device.vcStream);

			HANDLE hRecording = CreateEvent(NULL, false, false, RECORDING_STATUS_CHANGE);
			SetEvent( hRecording );
			CloseHandle(hRecording);

			hRecording = CreateEvent(NULL, false, false, RECORDING_ACTING);
			SetEvent( hRecording );
			CloseHandle(hRecording);
		}
	}
	else
		bResult = false;

	return bResult;
}

bool CEventMgrAction::OperatePTZ(const ec_Event_Action& EventAction)
{
	PTZAuthenticate ptzAuthenticate(
		(LPCWSTR)EventAction.target_device.ipaddress,
		(LPCWSTR)EventAction.target_device.username,
		(LPCWSTR)EventAction.target_device.password,
		EventAction.target_device.httpport,
		EventAction.ptz_action,
		EventAction.ptz_preset);

	CPTZAction ptzAction;
	ptzAction.SetPTZAuthenticate(ptzAuthenticate);
	return ptzAction.Action();
}

bool CEventMgrAction::SnapShot(const ec_Event_Action& EventAction)
{
	int nStreamId = GetStreamID(EventAction.target_device.cameraid);
	CSnapShot snapshot(EventAction.target_device, 1, m_strSnapshotFolder);
	return snapshot.Snapshot();
}

bool CEventMgrAction::PlaySound(const ec_Event_Action& EventAction)
{
	static string str = "beep";
	if (g_handle_sendeventaction == NULL)
	{
		g_sendeventaction = true;
		g_handle_sendeventaction = (HANDLE)::_beginthreadex(NULL, 0, send_event_action_to_user, (LPVOID)this, 0, NULL);
	}

	EnterCriticalSection(&m_criSec);
	g_quAction.push(str);
	LeaveCriticalSection(&m_criSec);
	return true;
}

bool CEventMgrAction::ExacuteFile(const ec_Event_Action& EventAction)
{
	static char buf[BUFSIZE];
	if (g_handle_sendeventaction == NULL)
	{
		g_sendeventaction = true;
		g_handle_sendeventaction = (HANDLE)::_beginthreadex(NULL, 0, send_event_action_to_user, (LPVOID)this, 0, NULL);
	}
	
	string str( EventAction.custom_path.begin(), EventAction.custom_path.end() );
	unsigned found = str.find_last_of("/\\");
	sprintf_s(buf, sizeof(buf), "%s \"%s\" %s", "start /b /d", str.substr(0,found).c_str(), str.substr(found+1).c_str());

	EnterCriticalSection(&m_criSec);
	g_quAction.push(buf);
	LeaveCriticalSection(&m_criSec);
	return true;
}

void CEventMgrAction::CloseEventAction()
{
	g_sendeventaction = false;

	if (g_handle_sendeventaction)
	{
		WaitForSingleObject( g_handle_sendeventaction, INFINITE );
		CloseHandle(g_handle_sendeventaction);
		g_handle_sendeventaction = NULL;
		g_quAction.empty();
	}
}