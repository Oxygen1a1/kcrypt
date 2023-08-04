#include <fltKernel.h>
#include <Hasher.hpp>
#include <SymCipher.hpp>
#include <ASymCipher.hpp>


#define printk(...)do{DbgPrintEx(77,0,__VA_ARGS__);}while(0)
//must include cng.lib
EXTERN_C auto DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING) {
	NTSTATUS status=STATUS_SUCCESS;
	drv->DriverUnload = [](PDRIVER_OBJECT)->void {

	};

	//test

	unsigned char plainText[2] = { 'a','\0' };

	//MD5 Test
	kcrypt::Md5Creator md5test;
	unsigned char md5Hash[20]{0};
	md5test.crypt(plainText,1, md5Hash, kcrypt::MD5::GetHashLength());
	char md5Str[40]{ 0 };
	kcrypt::hexToStr(md5Str, sizeof (md5Str), md5Hash, kcrypt::MD5::GetHashLength());
	printk("md5 crypt->%s\r\n", md5Str);

	//MD4 Test
	kcrypt::Md4Creator md4test;
	unsigned char md4Hash[20]{ 0 };
	md4test.crypt(plainText, 1, md4Hash, kcrypt::MD4::GetHashLength());
	char md4Str[40]{ 0 };
	kcrypt::hexToStr(md4Str, sizeof(md4Str), md4Hash, kcrypt::MD4::GetHashLength());
	printk("md4 crypt->%s\r\n", md4Str);

	//SHA1 TEST
	kcrypt::SHA1Creator sha1test;
	unsigned char sha1Hash[20]{ 0 };
	sha1test.crypt(plainText, 1, sha1Hash, kcrypt::SHA1::GetHashLength());
	char sha1Str[40]{ 0 };
	kcrypt::hexToStr(sha1Str, sizeof sha1Str, sha1Hash, kcrypt::SHA1::GetHashLength());
	printk("sha1 crypt->%s\r\n", sha1Str);
	
	//SHA256 TEST
	kcrypt::SHA256Creator sha256test;
	unsigned char sha256Hash[40]{ 0 };
	sha256test.crypt(plainText, 1, sha256Hash, kcrypt::SHA256::GetHashLength());
	char sha256Str[80]{0};
	kcrypt::hexToStr(sha256Str, sizeof sha256Str, sha256Hash, kcrypt::SHA256::GetHashLength());
	printk("sha256 crypt->%s\r\n", sha256Str);

	//DES test ecb
	unsigned char desPlainText[8] = { 0 };
	memset(desPlainText, 7, 8);
	kcrypt::DESCreator desTest;
	unsigned char desBuf[20]{ 0 };
	auto result = desTest.encrypt(desPlainText, sizeof desPlainText, desBuf, sizeof desBuf);
	char desStr[20]{ 0 };
	kcrypt::hexToStr(desStr, sizeof desStr, desBuf, 8);
	printk("des ecb str->%s\r\n", desStr);
	//decrypt test
	unsigned char decryptCode[8]{ 0 };
	desTest.decrypt(decryptCode, sizeof decryptCode, desBuf, result);


	//DES paterrn cbc test
	unsigned char desPlainTextCbc[16]{ 0 };
	memset(desPlainTextCbc, 7, 16);
	unsigned char iv[8] = { 0xb0,0x21,0x32,0x08,0x18,0x08,0xb4,0x93 };
	kcrypt::DESCreator descbcTest(nullptr, kcrypt::Mode::cbc,
		iv);
	unsigned char descbcBuf[20]{ 0 };
	result = descbcTest.encrypt(desPlainTextCbc, sizeof desPlainTextCbc, descbcBuf, sizeof descbcBuf);
	char descbcStr[40]{ 0 };
	kcrypt::hexToStr(descbcStr, sizeof descbcStr, descbcBuf, 8);
	printk("des cbc str->%s\r\n", descbcStr);
	//cbc des decrypt test
	unsigned char decryptcbcCode[20]{ 0 };
	descbcTest.decrypt(decryptcbcCode, sizeof decryptcbcCode, descbcBuf, result);


	//3DES test
	unsigned char tripedesKey[24] = { 0 };
	for (int i = 0; i < 8; i++) {
		tripedesKey[i] = (unsigned char)i + 1;
	}
	unsigned char tripledesPlaint[8]{ 0 };
	memset(tripledesPlaint, 7, 8);
	//set secret key
	kcrypt::TripleDESCreator tripleDesTest(tripedesKey);
	unsigned char tripleDesBuf[8]{ 0 };
	result = tripleDesTest.encrypt(tripledesPlaint, sizeof tripledesPlaint, tripleDesBuf, sizeof tripleDesBuf);
	char tripleDesStr[40]{ 0 };
	kcrypt::hexToStr(tripleDesStr, sizeof tripleDesStr, tripleDesBuf, result);
	printk("3des str->%s\r\n", tripleDesStr);
	//3 des decrypt test
	unsigned char decrypt3desCode[20]{ 0 };
	tripleDesTest.decrypt(decrypt3desCode, sizeof decrypt3desCode, tripleDesBuf, result);


	//AES128 test
	kcrypt::AESCreator aesTest;
	unsigned char aesPlainText[16]{ 0 };
	memset(aesPlainText, 7, 16);
	unsigned char aesBuf[16]{ 0 };
	char aesStr[40]{ 0 };
	unsigned char aesDecryptBuf[16]{ 0 };
	result = aesTest.encrypt(aesPlainText, sizeof aesPlainText, aesBuf, sizeof aesBuf);
	kcrypt::hexToStr(aesStr, sizeof aesStr, aesBuf, result);
	printk("aes str->%s\r\n", aesStr);
	//decrypt test
	aesTest.decrypt(aesDecryptBuf, sizeof aesDecryptBuf, aesBuf, result);


	//RC4 Test
	unsigned char rc4PlainText[1] = { 7 };
	unsigned char rc4Buf[1] = { 0 };
	char rc4Str[10] = { 0 };
	unsigned char rc4decryptCode[1] = { 0 };
	kcrypt::RC4Creator rc4test;
	result = rc4test.encrypt(rc4PlainText, sizeof rc4PlainText, rc4Buf, sizeof rc4Buf);
	kcrypt::hexToStr(rc4Str, sizeof rc4Str, rc4Buf, result);
	printk("rc4 str->%s\r\n", rc4Str);
	//RC4 is a stream cipher,so we need to create a new rc4Creator instance
	//so that we can confirm that stream key is same as we encrypt
	kcrypt::RC4Creator rc4Decrypt;
	rc4Decrypt.decrypt(rc4decryptCode, sizeof rc4decryptCode, rc4Buf, result);


	//RSA test
	unsigned char rsaPlainText[1] = { 7 };
	unsigned char rsaBuf[500] = { 0 };
	char rsaStr[40]{ 0 };
	unsigned char rsadecryptCode[1] = { 0 };
	kcrypt::RSACreator rsatest;
	auto [pubkey, pubkeysize] = rsatest.getPubKey();
	auto [prikey, prikeysize] = rsatest.getPriKey();
#pragma  warning(disable :4996)
	auto pubKeyStr = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'tmp');
	auto priKeyStr = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'tmp');
	memset(pubKeyStr, 0, PAGE_SIZE);
	memset(priKeyStr, 0, PAGE_SIZE);
	kcrypt::hexToStr(priKeyStr, PAGE_SIZE, prikey, prikeysize);
	kcrypt::hexToStr(pubKeyStr, PAGE_SIZE, pubkey, pubkeysize);
	printk("pub key ->%s\r\n pri key ->%s\r\n", pubKeyStr, priKeyStr);
	// You can leave arg5 and arg6 blank, 
	// as this will use the default public key for encryption
	// and the private key for decryption.
	result = rsatest.encrypt(rsaPlainText, sizeof rsaPlainText, rsaBuf, sizeof rsaBuf);
	kcrypt::hexToStr(rsaStr, sizeof rsaStr, rsaBuf, result);
	printk("rsa str->%s\r\n", rsaStr);
	//rsatest.decrypt(rsadecryptCode, sizeof rsadecryptCode, rsaBuf, result);
	//and you can fill any pubkey or private key to encrypt and decrypt 
	result = rsatest.encrypt(rsaPlainText, sizeof rsaPlainText,
		rsaBuf, sizeof rsaBuf, pubkey, pubkeysize);
	rsatest.decrypt(rsadecryptCode, sizeof rsadecryptCode, rsaBuf, result);
	ExFreePool(pubKeyStr);



	return status;
}