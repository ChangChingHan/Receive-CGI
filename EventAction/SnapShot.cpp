#include "StdAfx.h"
#include "SnapShot.h"
#include <atlimage.h>

#define		DIB_HEADER_MARKER			((WORD) ('M' << 8) | 'B')
#define		WIDTHBYTES(bits)			(((bits)   +   31)   /   32   *   4) 
#define		BMP_FILE_NAME				_T("%s\\%04d-%d-%d-%d-%d-%d-%d.bmp")
#define		JPG_FILE_NAME				_T("%s\\%04d-%d-%d-%d-%d-%d-%d.jpg")		

CSnapShot::CSnapShot(const ec_Camera& device, int nStreamId, CString strFileFolder)
:m_device(device),m_nStreamId(nStreamId),m_strFileFolder(strFileFolder)
{
}

CSnapShot::~CSnapShot(void)
{
}

bool CSnapShot::CheckFileFolder()
{
	bool bResult = true;

	CFileFind cfFind;
	if ( !cfFind.FindFile(m_strFileFolder) )
	{	
		if (CreateDirectory(m_strFileFolder, NULL) == false)
		{
			bResult = false;
		}
	}

	m_strFileFolder.Format(_T("%s\\%s-%s"), m_strFileFolder, m_device.cameraname, m_device.ipaddress);
	if ( !cfFind.FindFile(m_strFileFolder) )
	{	
		if (CreateDirectory(m_strFileFolder, NULL) == false)
		{
			bResult = false;
		}
	}

	return bResult;
}

void CSnapShot::GetBMPnJPGFileName(CString& strJPG, CString& strBMP)
{
	SYSTEMTIME hosttime;
	GetLocalTime(&hosttime);

	strBMP.Format(BMP_FILE_NAME, m_strFileFolder, hosttime.wYear, hosttime.wMonth, hosttime.wDay, hosttime.wHour, hosttime.wMinute, hosttime.wSecond, hosttime.wMilliseconds);
	strJPG.Format(JPG_FILE_NAME, m_strFileFolder, hosttime.wYear, hosttime.wMonth, hosttime.wDay, hosttime.wHour, hosttime.wMinute, hosttime.wSecond, hosttime.wMilliseconds);

}

bool CSnapShot::Snapshot()
{
	BITMAPINFOHEADER bih;
	uint8_t* picture_buf;
	bool bResult = false;

	if (CheckFileFolder())
	{
		CString csMappingName;
		csMappingName.Format(_T("Global\\%s-%d-%d"), 
			m_device.mac_address.MakeUpper(), 
			m_device.vcStream[m_nStreamId-1].stream_port, 
			m_nStreamId);

		HANDLE hMappingFile(NULL);

		hMappingFile = ::OpenFileMapping(FILE_MAP_ALL_ACCESS, TRUE, csMappingName);

		if((NULL != hMappingFile))
		{
			BITMAPINFOHEADER* pbih;
			DECODE_FILE_HEADER* decodehead;
			decodehead = (DECODE_FILE_HEADER*)::MapViewOfFile(hMappingFile, FILE_MAP_WRITE, 0, 0, 0);
			if (decodehead)
			{
				pbih = (BITMAPINFOHEADER*)((char*)decodehead + sizeof(DECODE_FILE_HEADER));
				memcpy(&bih, pbih, sizeof(BITMAPINFOHEADER));
				DWORD nSize = WIDTHBYTES( bih.biWidth * bih.biBitCount) * abs(bih.biHeight);
				picture_buf = (uint8_t*)pbih + sizeof(BITMAPINFOHEADER);

				CFile file;
				BITMAPFILEHEADER bmfHdr ={0};
				BITMAPINFOHEADER bmpHead = bih; 
				bmpHead.biSize = sizeof(BITMAPINFOHEADER);
				bmpHead.biHeight = (bih.biHeight);
				bmpHead.biBitCount = 32;
				DWORD nLineWidth = WIDTHBYTES( 32 * bmpHead.biWidth);
				bmpHead.biSizeImage =  nLineWidth * abs(bmpHead.biHeight);
				bmpHead.biPlanes = 1;
				bmpHead.biCompression = BI_RGB;
				bmpHead.biClrImportant = 0;
				bmpHead.biClrUsed = 0;

				bmfHdr.bfType = DIB_HEADER_MARKER;
				bmfHdr.bfSize = bmpHead.biSizeImage  + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
				bmfHdr.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + bmpHead.biSize + 0;
				CString csFilename, csJPGFileName;

				GetBMPnJPGFileName(csJPGFileName, csFilename);

				if (file.Open( csFilename.LockBuffer(), CFile::modeCreate | CFile::modeWrite))
				{
					BYTE *LPOFFSET = NULL;
					DWORD dwDIBSaveCnt = 0;
					// Write the file header
					file.Write((LPSTR)&bmfHdr, sizeof(BITMAPFILEHEADER));
					file.Write((LPSTR)&bmpHead, sizeof(BITMAPINFOHEADER));
					file.Write((unsigned char *)picture_buf,  bmpHead.biSizeImage);
					file.Close();

					CImage image;
					image.Load(csFilename);
					image.Save(csJPGFileName, Gdiplus::ImageFormatJPEG);
					CFile::Remove(csFilename);
					bResult = true;
				}
				else
					file.Close();
			}
			UnmapViewOfFile(decodehead);
		}

		CloseHandle(hMappingFile);
	}

	return bResult;
}