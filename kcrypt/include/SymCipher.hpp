#pragma once
#include <fltKernel.h>
#include <bcrypt.h>
#pragma warning(disable :4996)

namespace kcrypt {

#define symprintk(...) do { DbgPrintEx(77, 0, __VA_ARGS__); } while (0);
	template<typename Algorithm>
	class StreamCipher {
	public:
		StreamCipher(PUCHAR key=nullptr);
		~StreamCipher();
		ULONG encrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize);
		ULONG decrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize);

	private:
		PUCHAR _key;
		BCRYPT_ALG_HANDLE _hAlg;
		BCRYPT_KEY_HANDLE _hKey;
		PUCHAR _keyObj;

	};

	template<typename Algorithm>
	StreamCipher<Algorithm>::StreamCipher(PUCHAR key):_key(key) {

		do {

			NTSTATUS status = 0;
			//process key
			if (_key == nullptr) key = Algorithm::GetDefaultKey();
			_key = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Algorithm::GetKeySize(), 'sym');
			if (_key == nullptr) {
				symprintk("failed to create key space errcode->%08x\r\n", status);
				break;
			}
			memcpy(_key, key, Algorithm::GetKeySize());
			//open provider
			if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&_hAlg,
				Algorithm::GetAlgorithmName(), 0, 0))) {

				symprintk("failed to create algorithm provider! errcode->%08x\r\n", status);
				break;
			}
			ULONG objSize = 0,result=0;
			//get property
			if (!NT_SUCCESS(status = BCryptGetProperty(_hAlg, BCRYPT_OBJECT_LENGTH,
				(PUCHAR)&objSize, sizeof ULONG, &result, 0))) {
				symprintk("failed to get object size! errcode->%08x\r\n", status);
				break;
			}

			_keyObj = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, objSize, 'sym');
			if (_keyObj == nullptr) {
				symprintk("failed to create errcode->%08x\r\n", status);
				break;
			}
			
			//generate key handle for encrypt or decrypt
			if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(_hAlg, &_hKey,
				_keyObj, objSize, _key,
				Algorithm::GetKeySize(), 0
			))) {
				symprintk("failed to generate key! errcode->%08x\r\n",status);
				break;
			}
			return;
		} while (0);
		
		if (_keyObj) {

			ExFreePool(_keyObj);
			_key = 0;
		}
		if (_hAlg) {
			BCryptCloseAlgorithmProvider(_hAlg, 0);
			_hAlg = 0;
		}
		if (_hKey) {
			BCryptDestroyKey(_hKey);
			_hKey = 0;
		}
		if (_key) {
			ExFreePool(_key);
			_key = 0;
		}
		
	}
	template<typename Algorithm>
	StreamCipher<Algorithm>::~StreamCipher() {

		if (_keyObj) {

			ExFreePool(_keyObj);
			_key = 0;
		}
		if (_hAlg) {
			BCryptCloseAlgorithmProvider(_hAlg, 0);
			_hAlg = 0;
		}
		if (_hKey) {
			BCryptDestroyKey(_hKey);
			_hKey = 0;
		}
		if (_key) {
			ExFreePool(_key);
			_key = 0;
		}

	}
	template<typename Algorithm>
	ULONG StreamCipher<Algorithm>::encrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize) {
		if (!_hKey) return 0;
		
		NTSTATUS status = 0;
		ULONG result = 0;
		if (!NT_SUCCESS(status = BCryptEncrypt(_hKey, data, dataSize,
			0, 0, 0, cryptData, cryptSize, &result, 0))) {
			symprintk("failed to encrypt! errorcode->08%X\r\n",status);
			return 0;
		}
		else return result;

	}
	template<typename Algorithm>
	ULONG StreamCipher<Algorithm>::decrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize) {
		if (!_hKey) return 0;

		NTSTATUS status = 0;
		ULONG result = 0;
		if (!NT_SUCCESS(status = BCryptDecrypt(_hKey, cryptData, cryptSize,
			0, 0, 0, data, dataSize, &result, 0))) {
			symprintk("failed to decrypt! errorcode->08%X\r\n", status);
			return 0;
		}
		else return result;
			
	}
	class RC4 {
	public:
		static constexpr LPCWSTR GetAlgorithmName() {
			return BCRYPT_RC4_ALGORITHM;
		}
		static constexpr ULONG GetKeySize() {
			return 16; // 128-bit key.
		}
		static PUCHAR GetDefaultKey() {
			static unsigned char key[16] = { 0 };
			return key;
		}
	};
	
	using RC4Creator = StreamCipher<RC4>;

	enum class Mode {
		ecb,
		cbc,
		cfb,
		ccm,
		gcm
	};

	template<typename Algorithm>
	class BlockCipher {
	public:
		//ARG1 secret key ARG2 generate mode ARG3:IV
		BlockCipher(PUCHAR key=nullptr, Mode mod = Mode::ecb,PUCHAR iv=nullptr);
		~BlockCipher();
		ULONG encrypt(PUCHAR data,ULONG dataSize,PUCHAR cryptData,ULONG cryptSize);
		ULONG decrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize);
		PUCHAR  getcuriv() { return _iv; }
		PUCHAR  getlastiv() { return _preIv; }
		PUCHAR  getkey() { return _key; }
		bool setpreiv(PUCHAR lastIv);//lastIv only use for decrypting
		bool setiv(PUCHAR iv);//iv use for encrypting
	private:
		PUCHAR _key;//secret key
		BCRYPT_ALG_HANDLE _hAlg;//
		BCRYPT_KEY_HANDLE _hKey;//use for encrypt and decrypt
		PUCHAR _keyObj;
		Mode _mod;
		PUCHAR _iv;
		PUCHAR _preIv;
		ULONG _ivSize;
	};

	template<typename Algorithm>
	BlockCipher<Algorithm>::BlockCipher(PUCHAR key, Mode mod,PUCHAR iv):_key(key),_mod(mod),_iv(iv) {

		do {

			//create privoder handle
			auto status = BCryptOpenAlgorithmProvider(&_hAlg,
				Algorithm::GetAlgorithmName(), 0, 0);
			if (!NT_SUCCESS(status)) break;


			//query key object size
			ULONG keyObjSize = 0,result=0;
			status = BCryptGetProperty(_hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof ULONG, &result, 0);
			if (!NT_SUCCESS(status)) break;
			_keyObj = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,keyObjSize, 'sym');
			if (_keyObj == nullptr) break;


			//set iv if ecb not needed
			if (_key == nullptr) _key = Algorithm::GetDefaultKey();
			else {
				
				_key = (PUCHAR)ExAllocatePoolWithTag(PagedPool, Algorithm::GetBlockSize(), 'sym');
				if (_key == nullptr) break;
				memcpy(_key, key, Algorithm::GetBlockSize());
			}

			if (mod != Mode::ecb) {
				//query to get ivSize
				if (!NT_SUCCESS(BCryptGetProperty(
					_hAlg,
					BCRYPT_BLOCK_LENGTH,
					(PUCHAR)&_ivSize,
					sizeof(ULONG),
					&result,
					0))) break;
				//if not ecb pattren we need iv
				if (_iv == nullptr) {
					iv = Algorithm::GetDefaultIV();
				}
				
				//alloc memory to avoid local var
				_iv = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, _ivSize, 'sym');
				_preIv= (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, _ivSize, 'sym');
				if (_iv == nullptr || !_preIv) break;
				memcpy(_iv, iv, _ivSize);
				memset(_preIv, 0, _ivSize);
				
			}else { _iv = nullptr, _ivSize = 0,_preIv=nullptr; }
			//set pattern
			switch (_mod)
			{
			case kcrypt::Mode::ecb:
				status = BCryptSetProperty(_hAlg, BCRYPT_CHAINING_MODE,
					(PUCHAR)BCRYPT_CHAIN_MODE_ECB,
					sizeof(BCRYPT_CHAIN_MODE_ECB),
					0);
				break;
			case kcrypt::Mode::cbc:
				status = BCryptSetProperty(_hAlg, BCRYPT_CHAINING_MODE,
					(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
					sizeof(BCRYPT_CHAIN_MODE_CBC),
					0);
				break;
			case kcrypt::Mode::cfb:
				status = BCryptSetProperty(_hAlg, BCRYPT_CHAINING_MODE,
					(PUCHAR)BCRYPT_CHAIN_MODE_CFB,
					sizeof(BCRYPT_CHAIN_MODE_CFB),
					0);
				break;
			case kcrypt::Mode::ccm:
				status = BCryptSetProperty(_hAlg, BCRYPT_CHAINING_MODE,
					(PUCHAR)BCRYPT_CHAIN_MODE_CCM,
					sizeof(BCRYPT_CHAIN_MODE_CCM),
					0);
				break;
			case kcrypt::Mode::gcm:
				status = BCryptSetProperty(_hAlg, BCRYPT_CHAINING_MODE,
					(PUCHAR)BCRYPT_CHAIN_MODE_GCM,
					sizeof(BCRYPT_CHAIN_MODE_GCM),
					0);
				break;
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!NT_SUCCESS(status)) break;

			//to generate key handle for next encrypt and decrypt
			status = BCryptGenerateSymmetricKey(_hAlg, &_hKey, _keyObj,keyObjSize, _key, Algorithm::GetBlockSize(),0);
			if (!NT_SUCCESS(status)) {
				symprintk("failed to  generate key!\r\n");
				break;
			}

			return;
		} while (0);


		if (_hAlg) {

			BCryptCloseAlgorithmProvider(_hAlg,0);
			_hAlg = 0;
		}
		if (_hKey) {

			BCryptDestroyKey(_hKey);
			_hKey = 0;
		}
		if (_keyObj) {
			ExFreePool(_keyObj);
			_keyObj = 0;
		}
		if (_iv != nullptr) {
			ExFreePool(_iv);
			_iv = 0;
		}
		if (_preIv) {
			ExFreePool(_preIv);
			_preIv = 0;
		}
		if (_key != Algorithm::GetDefaultKey() && key) {
			ExFreePool(_key);
			_key = nullptr;
		}
		symprintk("failed to ctor!\r\n");
		
	}

	template <typename Algorithm>
	BlockCipher<Algorithm>::~BlockCipher() {
		if (_keyObj) {
			ExFreePool(_keyObj);
			_keyObj = 0;
		}

		if (_hAlg) {

			BCryptCloseAlgorithmProvider(_hAlg,0);
			_hAlg = 0;
		}
		if (_hKey) {

			BCryptDestroyKey(_hKey);
			_hKey = 0;
		}
		if (_iv != nullptr) {
			ExFreePool(_iv);
			_iv = 0;
		}
		if (_preIv) {
			ExFreePool(_preIv);
			_preIv = 0;
		}
		if (_key != Algorithm::GetDefaultKey() && _key) {
			ExFreePool(_key);
			_key = nullptr;
		}
	}

	template <typename Algorithm>
	ULONG BlockCipher<Algorithm>::encrypt(PUCHAR data, ULONG dataSize, PUCHAR cryptData, ULONG cryptSize) {
		if (!_hKey || !_hAlg ||!_keyObj) {
			return 0;
		}
		ULONG result = 0; 
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		unsigned char saveIv[8]{ 0 };
		if(_iv!=nullptr)
			memcpy(saveIv, _iv, 8);

		if (!NT_SUCCESS(status=BCryptEncrypt(_hKey, data, dataSize, 0, _iv,_ivSize,
			cryptData, cryptSize, &result, 0))) {

			symprintk("fialed to encrypt,errcode->08%x\r\n", status);
			return 0;
		}
		else {
			if (_iv != nullptr)
				memcpy(_preIv, saveIv, 8);
			return result;
		}
	}

	template<typename Algorithm>
	ULONG BlockCipher<Algorithm>::decrypt(PUCHAR data, ULONG dataSize,PUCHAR cryptData, ULONG cryptSize) {

		//decrypt
		if (!_hKey || !_hAlg || !_keyObj) {
			return 0;
		}
		ULONG result = 0;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		if (!NT_SUCCESS(status = BCryptDecrypt(_hKey,cryptData,cryptSize,0,_preIv
			,_ivSize,data,dataSize,&result,0))) {

			symprintk("failed to decrypt,errcode->08%x\r\n", status);
			return 0;
		}
		else return result;

	}

	template<typename Algorithm>
	inline bool BlockCipher<Algorithm>::setpreiv(PUCHAR preiv)
	{
		//IV not support ecb or preiv Invaild
		if (_mod == Mode::ecb || !MmIsAddressValid(preiv)) return false;
		
		if (preiv == _preIv) return true;

		auto tmpIv = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, _ivSize, 'sym');
		if (tmpIv == nullptr) {

			return false;
		}

		memcpy(tmpIv, preiv, _ivSize);
		ExFreePool(_preIv);
		this->_preIv = tmpIv;
		return true;
	}

	template<typename Algorithm>
	inline bool BlockCipher<Algorithm>::setiv(PUCHAR iv)
	{
		if (_mod == Mode::ecb || !MmIsAddressValid(iv)) return false;//IV not support ecb
		if (iv == _iv) return true;

		auto tmpIv = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, _ivSize, 'sym');
		if (tmpIv == nullptr) {

			return false;
		}
		memcpy(tmpIv, iv, _ivSize);
		ExFreePool(_iv);
		this->_iv = tmpIv;
		return true;

	}




	class DES {

	public:
		static constexpr LPCWSTR GetAlgorithmName() {
			return BCRYPT_DES_ALGORITHM;
		}
		static constexpr ULONG GetBlockSize() {
		
			return 8;
		}
		static PUCHAR GetDefaultKey(){
			//DES key size of  8 bytes
			static UCHAR key[8] = { 0 };
			return key;
		}
		static PUCHAR GetDefaultIV() {
			// DES block size is 8 bytes.
			static UCHAR iv[8] = { 0 };
			return iv;
		}
	};

	class TripleDES {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_3DES_ALGORITHM;
		}
		static constexpr ULONG GetBlockSize() {
			return 24;
		}
		static UCHAR* GetDefaultKey() {
			// 3DES supports key sizes of 21 bytes.
			static UCHAR key[24] = { 0 };
			return key;
		}
		static PUCHAR GetDefaultIV() {
			// 3DES block size is 8 bytes.
			static UCHAR iv[8] = { 0 };
			return iv;
		}
	};

	class AES {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_AES_ALGORITHM;
		}
		static constexpr ULONG GetBlockSize() {
			return 16;
		}
		static UCHAR* GetDefaultKey() {
			// AES supports key sizes of 16, 24, or 32 bytes.
			static UCHAR key[16] = { 0 };
			return key;
		}
		static UCHAR* GetDefaultIV() {
			// AES block size is 16 bytes.
			static UCHAR iv[16] = { 0 };
			return iv;
		}
	};
	
	using DESCreator = BlockCipher<DES>;
	using TripleDESCreator = BlockCipher<TripleDES>;
	using AESCreator = BlockCipher<AES>;


}

#pragma warning(default :4996)