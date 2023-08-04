#pragma once
#include <fltKernel.h>
#include <bcrypt.h>
#include <ntstrsafe.h>


namespace kcrypt {

	//由于这个项目用了crt库 不能用内核的了 只能这样
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
		BCRYPT_ALG_HANDLE hAlgorithm_;//算法提供者句柄
		BCRYPT_HASH_HANDLE hHash_;//hash对象句柄
		unsigned long hashObjSize_;
		void* hashObj_;//哈希对象
	};

	template <typename Algorithm>
	Hasher<Algorithm>::Hasher() {

		auto status = STATUS_UNSUCCESSFUL;
		do {

			status = BCryptOpenAlgorithmProvider(&hAlgorithm_, Algorithm::GetAlgorithmName(), nullptr, 0);
			if (!NT_SUCCESS(status)) break;

			unsigned long resultSize = 0;
			//询问属性
			status = BCryptGetProperty(hAlgorithm_, BCRYPT_OBJECT_LENGTH,
				(PUCHAR)&hashObjSize_, sizeof hashObjSize_, &resultSize, 0);
			if (!NT_SUCCESS(status)) {
				break;
			}

			hashObj_ = ExAllocatePoolWithTag(NonPagedPool, hashObjSize_, 'hash');
			if (hashObj_ == nullptr) break;
			//创建hash对象
			status = BCryptCreateHash(hAlgorithm_, &hHash_,(PUCHAR)hashObj_, hashObjSize_, 0, 0, 0);
			if (!NT_SUCCESS(status)) {

				break;
			}


			return;//成功
		} while (0);

		//走到这是不成功
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

			//先验证hash的长度是否正确
			//BCryptFinsihHash 很邪门,必须长度等同于hash值长度
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
			return 20;  // SHA-1的哈希值长度为160位，即20字节
		}
	};

	class SHA256 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA256_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 32;  // SHA-256的哈希值长度为256位，即32字节
		}
	};

	class SHA384 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA384_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 48;  // SHA-384的哈希值长度为384位，即48字节
		}
	};

	class SHA512 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_SHA512_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 64;  // SHA-512的哈希值长度为512位，即64字节
		}
	};

	class MD4 {
	public:
		static constexpr PCWSTR GetAlgorithmName() {
			return BCRYPT_MD4_ALGORITHM;
		}
		static constexpr ULONG GetHashLength() {
			return 16;  // MD4的哈希值长度为128位，即16字节
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

	//16进制转换成str
	void hexToStr(char* hexStr, ULONG len, PUCHAR hexArry, ULONG hexLen) {
		if (len < hexLen * 2) return;
		UNICODE_STRING uFuncName{ 0 };
		RtlInitUnicodeString(&uFuncName, L"sprintf");
		auto ___sprintf = (fnsprintf)MmGetSystemRoutineAddress(&uFuncName);
		for (unsigned int i = 0; i < hexLen; i++) {
			//只能从ntoskrnl.exe导出了 因为被stdio这个坑填了
			___sprintf(hexStr + i * 2,"%02x", hexArry[i]);
		}

	}


#pragma warning(default : 4996)
}
