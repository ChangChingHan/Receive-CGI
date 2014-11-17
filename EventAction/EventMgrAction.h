#pragma once


#ifdef IMPL_EVENT_ACTION
#define LIBAPI_EVENT_ACTION __declspec(dllexport)
#else
#define LIBAPI_EVENT_ACTION __declspec(dllimport)
#endif 

class CDataCeneter;

class LIBAPI_EVENT_ACTION CEventMgrAction
{
private:
	CDataCeneter*							m_pDataCenter;
	map<CString, vector<ec_Event_Action> >	m_mapEventAction;//mac - action
	struMail								m_mailInfo;
	vector<strucEventSeverity>				m_vcEventSeverity;
	vector<Cam_Group_Cam>					m_vcGroupCam;
	CString									m_strSnapshotFolder;

public:
	CRITICAL_SECTION						m_criSec;
	CEventMgrAction(void);
	~CEventMgrAction(void);

private:
	void RefreshMailInfo();
	void RefreshAction();
	int GetStreamID(int nCamID);
	void GetSnapshotFolder();
	void CreateLogFolder();
	

public:
	// for outside API 
	void RefreshData();
	void Initial();
	void PushEventInfo(const EventInfo& eventInfo);
	void CloseEventAction();

public:
	// for thread function
	bool SendEmail(const EventInfo& eventInfo, const ec_Event_Action& EventAction);
	bool StartRecording(const ec_Event_Action& EventAction);
	bool OperatePTZ(const ec_Event_Action& EventAction);
	bool SnapShot(const ec_Event_Action& EventAction);
	bool PlaySound(const ec_Event_Action& EventAction);
	bool ExacuteFile(const ec_Event_Action& EventAction);
	void GetEventAction(map<CString, vector<ec_Event_Action> >& mapEventAction);
	vector<ec_Event_Action> FilterActionByEventType(EVENTTYPE eventType, const vector<ec_Event_Action>& vcAction);
	string GetActionName(EVENT_ACTION evAction);
};
