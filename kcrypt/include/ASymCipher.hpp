#pragma once
#include <fltkernel.h>
#include <bcrypt.h>

namespace kcrypt {
#pragma warning(disable :4996)
#define asymprink(...)do{DbgPrintEx(77,0,__VA_ARGS__);}while(0)
	struct keyInfo {
		PUCHAR key;
		ULONG keySize;
	};

	
	template<typename Algorithm>
	class ASymCipher {
		
	public:
		
		ASymCipher(ULONG keySize=512);
		~ASymCipher();
		ULONG encrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize,PUCHAR pubKey=nullptr,ULONG pubSize=0);
		ULONG decrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize,PUCHAR priKey=nullptr,ULONG priSize=0);
		keyInfo constexpr getPriKey() { return { _priKey,_priSize}; }
		keyInfo constexpr getPubKey() { return { _pubKey ,_pubSize}; }


		ASymCipher& operator=(ASymCipher&) = delete;
		ASymCipher& operator=(ASymCipher&&) = delete;
		ASymCipher(ASymCipher&) = delete;
	private:
		BCRYPT_ALG_HANDLE _hAlg;//create when open alg provider
		BCRYPT_KEY_HANDLE _hKey;//use for encrypt and decrypt
		PUCHAR _priKey;
		PUCHAR _pubKey;
		ULONG _pubSize;
		ULONG _priSize;
	private:
		bool rsaCheck(ULONG cbKeySize, ULONG cbData, BOOLEAN bEncrypt);
		
	};

	
	template<typename Algorithm>
	inline ASymCipher<Algorithm>::ASymCipher(ULONG keySize)
	{
		do {
			//check key size correct
			if (keySize != 512 && keySize != 1024 && keySize != 2048 && keySize != 4096) {
				asymprink("key len error!\r\n");
				break;
			}
			

			NTSTATUS status = 0;
			if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&_hAlg,
				Algorithm::GetAlgorithmName(), 0, 0))) {
				asymprink("failed to open alg provider! errcode->%08x\r\n",status);
				break;
			}

			//generate key pair and must call BCryptFinalizeKeyPair 
			if (!NT_SUCCESS(status = BCryptGenerateKeyPair(_hAlg, &_hKey, keySize, 0))) {
				asymprink("failed to generate key pair! errcode->08%x\r\n", status);
				break;
			}

			//if call BCryptFinalizeKeyPair we can not call BCryptSetProperty anymore
			if (!NT_SUCCESS(status = BCryptFinalizeKeyPair(_hKey, 0))) {
				asymprink("failed to finalize key pair! errcode->%08x\r\n", status);
				break;
			}

			//get public key and private key size
			if (!NT_SUCCESS(status = BCryptExportKey(_hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, 0, &_pubSize, 0))) {

				asymprink("failed to get pub key size! errcode->%08x\r\n", status);
				break;
			}
			if (!NT_SUCCESS(status = BCryptExportKey(_hKey, 0, BCRYPT_RSAPRIVATE_BLOB, 0, 0, &_priSize, 0))) {

				asymprink("failed to get private key size! errcode->%08x\r\n", status);
				break;
			}
			_pubKey = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, _pubSize, 'asym');
			_priKey= (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, _priSize, 'asym');
			if (!_priKey || !_pubKey) {
				asymprink("failed to alloc mem for key! errcode->%08x\r\n", status);
				break;
			}
			//get public and private key
			if (!NT_SUCCESS(status = BCryptExportKey(_hKey, 0, BCRYPT_RSAPUBLIC_BLOB, _pubKey, _pubSize, &_pubSize, 0))) {

				asymprink("failed to get pub key! errcode->%08x\r\n", status);
				break;
			}
			if (!NT_SUCCESS(status = BCryptExportKey(_hKey, 0, BCRYPT_RSAPRIVATE_BLOB, _priKey, _priSize, &_priSize, 0))) {

				asymprink("failed to get private key! errcode->%08x\r\n", status);
				break;
			}

			return;

		} while (0);

		//fault or err
		if (_hKey) {

			BCryptDestroyKey(_hKey);
			_hKey = 0;
		}
		if (_hAlg) {
			BCryptCloseAlgorithmProvider(_hAlg,0);
			_hAlg = 0;
		}
		if (_priKey) {
			ExFreePool(_priKey);
			_priKey = 0;
		}
		if (_pubKey) {
			ExFreePool(_pubKey);
			_pubKey = 0;

		}
	}

	template<typename Algorithm>
	inline ASymCipher<Algorithm>::~ASymCipher()
	{
		if (_hKey) {

			BCryptDestroyKey(_hKey);
			_hKey = 0;
		}
		if (_hAlg) {
			BCryptCloseAlgorithmProvider(_hAlg,0);
			_hAlg = 0;
		}
		if (_priKey) {
			ExFreePool(_priKey);
			_priKey = 0;
		}
		if (_pubKey) {
			ExFreePool(_pubKey);
			_pubKey = 0;

		}

	}

	//if arg5 isn't nullptr means that we need to import a new key handle to encrypt
	template<typename Algorithm>
	inline ULONG ASymCipher<Algorithm>::encrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize, PUCHAR pubKey,ULONG pubSize)
	{
		if (!_hKey) return 0;
		if (!rsaCheck(pubSize ? pubSize :_pubSize, dataSize, true)) {
			asymprink("key size or data size err!\r\n");
			return 0;
		}
		ULONG result=0;
		NTSTATUS status = 0;
		if (pubKey == nullptr) {
			//using pkcs1 padding and defualt public key
			if (!NT_SUCCESS(status = BCryptEncrypt(_hKey, data, dataSize, 0, 0, 0, cryptData,
				cryptSize, &result, BCRYPT_PAD_PKCS1))) {
				asymprink("failed to encrypt! errcode->%x\r\n", status);
				return 0;
			}
			else return result;

		}
		else {
			//we need open new hAlg and create new key handle(public key)
			BCRYPT_ALG_HANDLE hAlg = nullptr;
			BCRYPT_KEY_HANDLE hKey = nullptr;
			do {
				if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, 
					Algorithm::GetAlgorithmName(), 0, 0))) {
					asymprink("failed to open provider errcode->%08x\r\n", status);
					break;
				}

				//import key handle
				if (!NT_SUCCESS(status = BCryptImportKeyPair(hAlg
					, nullptr, BCRYPT_RSAPUBLIC_BLOB
					, &hKey, pubKey, pubSize
					, BCRYPT_NO_KEY_VALIDATION))) {
					asymprink("failed to get key handle errcode->%x\r\n", status);
					break;
				}
				
				//using pkcs1 padding and defualt public key
				if (!NT_SUCCESS(status = BCryptEncrypt(hKey, data, dataSize, 0, 0, 0, cryptData,
					cryptSize, &result, BCRYPT_PAD_PKCS1))) {
					asymprink("failed to encrypt! errcode->%x\r\n", status);
					result = 0;
					break;
				}
				else break;
				
			} while (0);
			
			if (hKey) {
				BCryptDestroyKey(hKey);
			}
			if (hAlg) {
				BCryptCloseAlgorithmProvider(hAlg, 0);
			}
			return result;

		}

	}

	//if arg5 isn't nullptr means that we need to import a new key handle to decrypt
	template<typename Algorithm>
	inline ULONG ASymCipher<Algorithm>::decrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize, PUCHAR priKey,ULONG priSize)
	{
		if (!_hKey) return 0;
		if (!rsaCheck(priSize ? priSize :_priSize, dataSize, false)) {
			asymprink("key size or data size err!\r\n");
			return 0;
		}
		ULONG result = 0;
		NTSTATUS status = 0;
		//using pkcs1 padding
		if (priKey == nullptr) {
			if (!NT_SUCCESS(status = BCryptDecrypt(_hKey, cryptData, cryptSize, 0, 0, 0, data,
				dataSize, &result, BCRYPT_PAD_PKCS1))) {
				asymprink("failed to decrypt! errcode->%x\r\n", status);
				return 0;
			}
			else return result;

		}
		else {

			//we need open new hAlg and create new key handle(public key)
			BCRYPT_ALG_HANDLE hAlg = nullptr;
			BCRYPT_KEY_HANDLE hKey = nullptr;
			do {
				if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg,
					Algorithm::GetAlgorithmName(), 0, 0))) {
					asymprink("failed to open provider errcode->%08x\r\n", status);
					break;
				}

				//import key handle
				if (!NT_SUCCESS(status = BCryptImportKeyPair(hAlg
					, nullptr, BCRYPT_RSAPRIVATE_BLOB
					, &hKey, priKey, priSize
					, BCRYPT_NO_KEY_VALIDATION))) {
					asymprink("failed to get key handle errcode->%08x\r\n", status);
					break;
				}

				//using pkcs1 padding and defualt public key
				if (!NT_SUCCESS(status = BCryptDecrypt(hKey, cryptData, cryptSize, 0, 0, 0, data,
					dataSize, &result, BCRYPT_PAD_PKCS1))) {
					asymprink("failed to decrypt! errcode->%x\r\n", status);
					result = 0;
					break;
				}
				else break;

			} while (0);

			if (hKey) {
				BCryptDestroyKey(hKey);
			}
			if (hAlg) {
				BCryptCloseAlgorithmProvider(hAlg, 0);
			}
			return result;

		}

	}


	/*
	the length of the content that can be encrypted
	depends on the bis size of the key.
	For 512bit key:
	Public key length: 91, Private key: 155
	For 1024bit:
	Public key: 155, Private key: 283
	For 2048bit:
	Public key: 283, Private key: 539
	For 4096bit:
	Public key: 539, Private key: 1051
	*/
	template<typename Algorithm>
	inline bool ASymCipher<Algorithm>::rsaCheck(ULONG cbKeySize, ULONG cbData, BOOLEAN bEncrypt)
	{
		if (bEncrypt)
		{
			switch (cbKeySize)
			{
			case 91: // 512bit
				if (cbData > 64)
					return FALSE;
				break;
			case 155: // 1024bit
				if (cbData > 128)
					return FALSE;
				break;
			case 283: // 2048bit
				if (cbData > 256)
					return FALSE;
				break;
			case 539: // 4096bit
				if (cbData > 512)
					return FALSE;
				break;
			default:
				return FALSE;
				break;
			}
			/*if (cbKeySize - cbData > 27)
				return TRUE;
			else
				return FALSE;*/
			return TRUE;
		}
		else
		{
			switch (cbKeySize)
			{
			case 155: // 512bit
			case 283: // 1024bit
			case 539: // 2048bit
			case 1051: // 4096bit
				return TRUE;
				break;
			default:
				return FALSE;
				break;
			}
		}
	}


	
	class RSA {
	public:
		static constexpr LPCWSTR GetAlgorithmName() {
			return BCRYPT_RSA_ALGORITHM;
		}

	};

	class DSA {
	public:
		static constexpr LPCWSTR GetAlgorithmName() {
			return BCRYPT_DSA_ALGORITHM;
		}

	};

	using RSACreator = ASymCipher<RSA>;
#pragma warning(default :4996)
}