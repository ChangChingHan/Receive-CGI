#include "stdafx.h"
#include "Crypto.h"

const string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

CCrypto::~CCrypto()
{
	if(m_file)
		m_file.Close();

	if(m_hHash)
		::CryptDestroyHash(m_hHash);

	if(m_hKey)
		::CryptDestroyKey(m_hKey);

	if(m_hCryptProv)
		::CryptReleaseContext(m_hCryptProv, 0);
}

string CCrypto::GetEncodeString(unsigned char const* src, unsigned int len)
{
	if (m_CryptoType == CRYPTO_BASE_64)
	{
		return base64_encode(src, len);
	}
	else
	{
		return "NULL";
	}
}

string CCrypto::GetDecodeString(string& src)
{
	if (m_CryptoType == CRYPTO_BASE_64)
	{
		return base64_decode(src);
	}
	else if(m_CryptoType == CRYPTO_WIN)
	{
		USES_CONVERSION;
		CString str = A2W(src.c_str());
		str = DecryptPassword(str);
		return W2A(str);

	}
	else
	{
		return "NULL";
	}
}

bool CCrypto::is_base64(unsigned char c) 
{
  return (isalnum(c) || (c == '+') || (c == '/'));
}

string CCrypto::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) 
{
  string ret;
  int i = 0, j = 0;
  unsigned char char_array_3[3], char_array_4[4];

  while (in_len--)
	{
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) 
		{
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

string CCrypto::base64_decode(string const& encoded_string) 
{
  int in_len = (int)encoded_string.size();
  int i = 0, j = 0, in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) 
	{
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) 
	{
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) 
	{
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) 
			ret += char_array_3[j];
  }

  return ret;
}

void CCrypto::SetCryptoType(CRYPTO_MODE cryType)
{
	m_CryptoType = cryType;
	if (m_CryptoType == CRYPTO_WIN)
	{
		if(!::CryptAcquireContext(&m_hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))	//Fix For Vista/Win7 by Hank
			return;
		if(!::CryptCreateHash(m_hCryptProv, CALG_MD5, 0, 0, &m_hHash)) 
			return;

		DeriveKey(_T("Encrypt!@#$%^&*()_+-~`"));
	}
}

bool CCrypto::DeriveKey(CString strPassword)
{
	//	Return failure if we don't have a context or hash.
	if(m_hCryptProv == NULL || m_hHash == NULL)
		return false;

	//	If we already have a hash, trash it.
	if(m_hHash)
	{
		CryptDestroyHash(m_hHash);
		m_hHash = NULL;
		if(!CryptCreateHash(m_hCryptProv, CALG_MD5, 0, 0, &m_hHash)) 
			return false;
	}

	//	If we already have a key, destroy it.
	if(m_hKey)
	{
		::CryptDestroyKey(m_hKey);
		m_hKey = NULL;
	}

	//	Hash the password. This will have a different result in UNICODE mode, as it
	//	will hash the UNICODE string (this is by design, allowing for UNICODE passwords, but
	//	it's important to be aware of this behaviour.
	if(!CryptHashData(m_hHash, (const BYTE*)strPassword.GetString(), strPassword.GetLength() * sizeof(TCHAR), 0)) 
		return false;

	//	Create a session key based on the hash of the password.
	if(!CryptDeriveKey(m_hCryptProv, CALG_RC2, m_hHash, CRYPT_EXPORTABLE, &m_hKey))
		return false;

	//	And we're done.
	return true;
}

bool CCrypto::Encrypt(const CObject& serializable, CByteArray& arData)
{
	//	Return failure if we don't have a context or key.
	if(m_hCryptProv == NULL || m_hKey == NULL)
		return false;

	//	Return failure if the object is not serializable.
	if(serializable.IsSerializable() == FALSE)
		return false;

	//	Before we write to the file, trash it.
	m_file.SetLength(0);

	//	Create a storing archive from the memory file.
	CArchive ar(&m_file, CArchive::store);

	//	We know that serialzing an object will not change it's data, as we can
	//	safely use a const cast here.

	//	Write the data to the memory file.
	const_cast<CObject&>(serializable).Serialize(ar);

	//	Close the archive, flushing the write.
	ar.Close();

	//	Encrypt the contents of the memory file and store the result in the array.
	return InternalEncrypt(arData);
}

bool CCrypto::Decrypt(const CByteArray& arData, CObject& serializable)
{
	//	Return failure if we don't have a context or key.
	if(m_hCryptProv == NULL || m_hKey == NULL)
		return false;

	//	Return failure if the object is not serializable.
	if(serializable.IsSerializable() == FALSE)
		return false;

	//	Decrypt the contents of the array to the memory file.
	if(InternalDecrypt(arData) == false)
		return false;

	//	Create a reading archive from the memory file.
	CArchive ar(&m_file, CArchive::load);

	//	Read the data from the memory file.
	serializable.Serialize(ar);

	//	Close the archive.
	ar.Close();

	//	And we're done.
	return true;
}

bool CCrypto::Encrypt(const CString& str, CByteArray& arData)
{
	//	Return failure if we don't have a context or key.
	if(m_hCryptProv == NULL || m_hKey == NULL)
		return false;

	//	Before we write to the file, trash it.
	m_file.SetLength(0);

	//	Create a storing archive from the memory file.
	CArchive ar(&m_file, CArchive::store);

	//	Write the string to the memory file.
	ar << str;

	//	Close the archive, flushing the write.
	ar.Close();

	//	Encrypt the contents of the memory file and store the result in the array.
	return InternalEncrypt(arData);
}

CString CCrypto::DecryptPassword(CString& csEncrypt)
{
	CString csDecrypt;
	CByteArray cbArray2;

	LPCSTR lpSTR;
	USES_CONVERSION;
	lpSTR = W2A(csEncrypt.LockBuffer());
	csEncrypt.UnlockBuffer();

	unsigned char hexdata[32];

	memset(hexdata, 0, sizeof(unsigned char)*32);

	strtohex(lpSTR, hexdata);

	cbArray2.SetSize(csEncrypt.GetLength()/2);

	for(int iTemp = 0; iTemp < (csEncrypt.GetLength()/2); iTemp++)
	{
		cbArray2[iTemp] = (BYTE)hexdata[iTemp];
	}

	Decrypt(cbArray2, csDecrypt);


	return csDecrypt;
}

void CCrypto::strtohex(const char *str, unsigned char *hex)
{
	int i,len = strlen(str);
	char* t;
	unsigned char* x;

	for(i=0,t=(char *)str,x=hex;i<len;i+=2,x++,t+=2)
	{
		if(*t >= '0' && *t <= '9')
		{
			*x = ((*t & 0x0f) << 4);
		}
		else
		{
			char h = 0x0a + tolower(*t) - 'a';
			*x = (h << 4) ;
		}
		if(*(t+1) >= '0' && *(t+1) <= '9')
		{
			*x |= (*(t+1) & 0x0f);
		}
		else
		{
			char l = 0x0a + tolower(*(t+1)) - 'a';
			*x += l;
		}
	}
}
bool CCrypto::Decrypt(const CByteArray& arData, CString& str)
{
	//	Return failure if we don't have a context or key.
	if(m_hCryptProv == NULL || m_hKey == NULL)
		return false;

	//	Decrypt the contents of the array to the memory file.
	if(InternalDecrypt(arData) == false)
		return false;

	//	Create a reading archive from the memory file.
	CArchive ar(&m_file, CArchive::load);

	//	Read the data from the memory file.
	ar >> str;

	//	Close the archive.
	ar.Close();

	//	And we're done.
	return true;
}

bool CCrypto::InternalEncrypt(CByteArray& arDestination)
{
	//	Get the length of the data in memory. Increase the capacity to handle the size of the encrypted data.
	ULONGLONG uLength = m_file.GetLength();
	ULONGLONG uCapacity = uLength * 2;
	m_file.SetLength(uCapacity);

	//	Acquire direct access to the memory.
	BYTE* pData = m_file.Detach();

	//	We need a DWORD to tell encrypt how much data we're encrypting.
	DWORD dwDataLength = static_cast<DWORD>(uLength);

	//	Now encrypt the memory file.
	if(!::CryptEncrypt(m_hKey, NULL, TRUE, 0, pData, &dwDataLength, static_cast<DWORD>(uCapacity)))
	{
		//	Free the memory we release from the memory file.
		delete [] pData;

		return false;
	}	

	//	Assign all of the data we have encrypted to the byte array- make sure anything 
	//	already in the array is trashed first.
	arDestination.RemoveAll();
	arDestination.SetSize(static_cast<INT_PTR>(dwDataLength));
	memcpy(arDestination.GetData(), pData, dwDataLength);

	//	Free the memory we release from the memory file.
	delete [] pData;

	return true;
}


//	Decrypt the contents of the passed array and store in the memory file.
bool CCrypto::InternalDecrypt(const CByteArray& arSource)
{
	//	Trash the file.
	m_file.SetLength(0);

	//	Write the contents of the byte array to the memory file.
	m_file.Write(arSource.GetData(), static_cast<UINT>(arSource.GetCount()));
	m_file.Flush();

	//	Acquire direct access to the memory file buffer.
	BYTE* pData = m_file.Detach();

	//	We need a DWORD to tell decrpyt how much data we're encrypting.
	DWORD dwDataLength = static_cast<DWORD>(arSource.GetCount());
	DWORD dwOldDataLength = dwDataLength;

	//	Now decrypt the data.
	if(!::CryptDecrypt(m_hKey, NULL, TRUE, 0, pData, &dwDataLength))
	{
		//	Free the memory we release from the memory file.
		delete [] pData;

		return false;
	}

	//	Set the length of the data file, write the decrypted data to it.
	m_file.SetLength(dwDataLength);
	m_file.Write(pData, dwDataLength);
	m_file.Flush();
	m_file.SeekToBegin();

	//	Free the memory we release from the memory file.
	delete [] pData;
	return true;
}