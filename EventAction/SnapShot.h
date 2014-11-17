#pragma once

class CSnapShot
{
public:
	CSnapShot(const ec_Camera& device, int nStreamId, CString strFileFolder);
	~CSnapShot(void);

private:
	CString			m_strFileFolder;
	ec_Camera		m_device;
	int				m_nStreamId;

private:
	bool CheckFileFolder();
	void GetBMPnJPGFileName(CString& strJPG, CString& strBMP);

public:
	void SetDeviceInfo(const ec_Camera& device){m_device=m_device;};
	void SetStreamId(int nStreamId){m_nStreamId=nStreamId;};
	void SetSnapshotFolder(CString strFileFolder){m_strFileFolder=strFileFolder;};
	bool Snapshot();

};
