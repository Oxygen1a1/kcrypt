#pragma once
#include <fltKernel.h>
#include <bcrypt.h>
#include <ntstrsafe.h>


namespace kcrypt {

	//���������Ŀ����crt�� �������ں˵��� ֻ������
	using fnsprintf = int(*)(char* _DstBuf,const char* _Format, ...);
#pragma warning(disable : 4996)
#define hashprintk(...)do{DbgPrintEx(77,0,__VA_ARGS__);}while(0);

	template <typename Algorithm>
	class Hasher {
	public:
		Hasher();
		~Hasher();
		bool crypt(PUCHAR data, ULONG size, PUCHAR hash, ULONG hash_len);
		Hasher(const Hasher&) = delete;
		Hasher(Hasher&&) = delete;
		Hasher& operator=(Hasher&) = delete;
	private:
		BCRYPT_ALG_HANDLE hAlgorithm_;//�㷨�ṩ�߾��
		BCRYPT_HASH_HANDLE hHash_;//hash������
		unsigned long hashObjSize_;
		void* hashObj_;//��ϣ����
	};

	template <typename Algorithm>
	Hasher<Algorithm>::Hasher() {

		auto status = STATUS_UNSUCCESSFUL;
		do {

			status = BCryptOpenAlgorithmProvider(&hAlgorithm_, Algorithm::GetAlgorithmName(), nullptr, 0);
			if (!NT_SUCCESS(status)) break;

			unsigned long resultSize = 0;
			//ѯ������
			status = BCryptGetProperty(hAlgorithm_, BCRYPT_OBJECT_LENGTH,
				(PUCHAR)&hashObjSize_, sizeof hashObjSize_, &resultSize, 0);
			if (!NT_SUCCESS(status)) {
				break;
			}

			hashObj_ = ExAllocatePoolWithTag(NonPagedPool, hashObjSize_, 'hash');
			if (hashObj_ == nullptr) break;
			//����hash����
			status = BCryptCreateHash(hAlgorithm_, &hHash_,(PUCHAR)hashObj_, hashObjSize_, 0, 0, 0);
			if (!NT_SUCCESS(status)) {

				break;
			}


			return;//�ɹ�
		} while (0);

		//�ߵ����ǲ��ɹ�
		if (hashObj_) {
			ExFreePool(hashObj_);
			hashObj_ = 0;
		}
		if (hAlgorithm_) {
			BCryptCloseAlgorithmProvider(hAlgorithm_, 0);
			hAlgorithm_ = 0;
		}
		if (hHash_) {
			BCryptDestroyHash(hHash_);
			hHash_ = 0;
		}
		
		hashprintk("failed to ctor!\r\n");

	}
	template <typename Algorithm>
	Hasher<Algorithm>::~Hasher() {

		if (hashObj_) {
			ExFreePool(hashObj_);
			hashObj_ = 0;
		}
		if (hAlgorithm_) {
			BCryptCloseAlgorithmProvider(hAlgorithm_,0);
			hAlgorithm_ = 0;
		}
		if (hHash_) {
			BCryptDestroyHash(hHash_);
			hHash_ = 0;
		}
	}
	template <typename Algorithm>
	bool Hasher<Algorithm>::crypt(PUCHAR data, ULONG size, PUCHAR hash, ULONG hash_len) {
		if (hHash_ && hashObj_ && hAlgorithm_) {

			//����֤hash�ĳ����Ƿ���ȷ
			//BCryptFinsihHash ��а��,���볤�ȵ�ͬ��hashֵ����
			if (Algorithm::GetHashLength() > hash_len)return false;
			auto status = STATUS_UNSUCCESSFUL;

			status = BCryptHashData(hHash_, data, size, 0);
			if (!NT_SUCCESS(status)) return false;

			status = BCryptFinishHash(hHash_, hash, Algorithm::GetHashLength(), 0);
			if (!NT_SUCCESS(status)) return false;
			
			return true;
		}
		
		return false;
	}

	class SHA1 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA1_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 20;  // SHA-1�Ĺ�ϣֵ����Ϊ160λ����20�ֽ�
		}
	};

	class SHA256 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA256_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 32;  // SHA-256�Ĺ�ϣֵ����Ϊ256λ����32�ֽ�
		}
	};

	class SHA384 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA384_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 48;  // SHA-384�Ĺ�ϣֵ����Ϊ384λ����48�ֽ�
		}
	};

	class SHA512 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA512_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 64;  // SHA-512�Ĺ�ϣֵ����Ϊ512λ����64�ֽ�
		}
	};

	class MD4 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_MD4_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 16;  // MD4�Ĺ�ϣֵ����Ϊ128λ����16�ֽ�
		}
	};

	class MD5 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {

			return BCRYPT_MD5_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 16;
		}
	};

	using Md4Creator = Hasher<MD4>;
	using Md5Creator = Hasher<MD5>;
	using SHA1Creator = Hasher<SHA1>;
	using SHA256Creator = Hasher<SHA256>;
	using SHA384Creator = Hasher<SHA384>;
	using SHA512Creator = Hasher<SHA512>;

	//16����ת����str
	void hexToStr(char* hexStr, ULONG len, PUCHAR hexArry, ULONG hexLen) {
		if (len < hexLen * 2) return;
		UNICODE_STRING uFuncName{ 0 };
		RtlInitUnicodeString(&uFuncName, L"sprintf");
		auto ___sprintf = (fnsprintf)MmGetSystemRoutineAddress(&uFuncName);
		for (unsigned int i = 0; i < hexLen; i++) {
			//ֻ�ܴ�ntoskrnl.exe������ ��Ϊ��stdio���������
			___sprintf(hexStr + i * 2,"%02x", hexArry[i]);
		}

	}


#pragma warning(default : 4996)
}
