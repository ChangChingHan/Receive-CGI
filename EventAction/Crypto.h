#include "stdafx.h"
#include "Wincrypt.h"

enum CRYPTO_MODE
{
	NON_CRYPTO = 0,
	CRYPTO_BASE_64,
	CRYPTO_WIN
};

class CCrypto
{
public:
	CCrypto():m_hCryptProv(NULL), m_hKey(NULL), m_hHash(NULL){};
	CCrypto(CRYPTO_MODE cryType){SetCryptoType(cryType);}
	~CCrypto();

	void SetCryptoType(CRYPTO_MODE cryType);
	string GetEncodeString(unsigned char const* , unsigned int len);
	string GetDecodeString(string& s);

private:
	CRYPTO_MODE m_CryptoType;

	/************************************************************************/
	/* BASE64
	/************************************************************************/
	string base64_encode(unsigned char const* , unsigned int len);
	string base64_decode(std::string const& s);
	bool is_base64(unsigned char c);

	/************************************************************************/
	/* Win Crypto
	/************************************************************************/
	HCRYPTPROV m_hCryptProv;
	HCRYPTKEY m_hKey;
	HCRYPTHASH m_hHash;
	CMemFile m_file;

	bool DeriveKey(CString strPassword);
	bool Encrypt(const CObject& serializable, CByteArray& arData);
	
	bool Decrypt(const CByteArray& arData, CObject& serializable);
	bool Decrypt(const CByteArray& arData, CString& str);

	bool Encrypt(const CString& str, CByteArray& arData);
	
	CString DecryptPassword(CString& csEncrypt);
	void strtohex(const char *str, unsigned char *hex);
	bool InternalEncrypt(CByteArray& arDestination);
	bool InternalDecrypt(const CByteArray& arSource);

};


