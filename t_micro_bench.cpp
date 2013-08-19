#include <iostream>
#include <vector>
#include <numeric>
#include <complex>
#include <cstdlib>
#include <sys/time.h>                // for gettimeofday()

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

using namespace std;

#define AES_KEY_LEN    32
#define KEY_ROTATION_REPEAT_TIME   1000
#define KEY_GEN_REPEAT_TIME   100

#define BLOCK_SIZE  4096
unsigned char block[BLOCK_SIZE];
unsigned char buf[2*BLOCK_SIZE];
static const unsigned char aes_key[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

void
rsa_gen_time()
{
    timeval t1, t2;
    double elapsedTime;
	std::vector<double> v;
	// start timer
	for (int i = 0; i < KEY_GEN_REPEAT_TIME; i++) {
	    // do something
		RSA *rsa = NULL;
		rsa = RSA_new();

		// generate a 1024-bit long RSA public-private key pair
    	gettimeofday(&t1, NULL);
		//rsa = RSA_generate_key(1024, 0x10001, NULL, NULL);
        BIGNUM *wggkey = BN_new();
        BN_set_word(wggkey,0x10001);
        RSA_generate_key_ex(rsa,1024,wggkey,NULL);
        BN_free(wggkey);
		gettimeofday(&t2, NULL);
		RSA_free(rsa);
		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
	}
	// stop timer

	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	// cout << "Time to generate a RSA key pair is: " << elapsedTime/KEY_GEN_REPEAT_TIME << " ms.\n";
	cout << "RSA keygen mean is: " << mean << " ms, std dev is: " << stdev << " ms.\n";
}

void hash_test()
{
	timeval t1, t2;
    double elapsedTime;
	unsigned char hash[32];
	std::vector<double> v;
	for (int i = 0; i < KEY_GEN_REPEAT_TIME; i++) {
		// md5 hash of block
    	gettimeofday(&t1, NULL);
		MD5(block, BLOCK_SIZE, hash);
		gettimeofday(&t2, NULL);

		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
	}

	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	// cout << "Time to generate a RSA key pair is: " << elapsedTime/KEY_GEN_REPEAT_TIME << " ms.\n";
	cout << "MD5 hash mean is: " << mean << " ms, std dev is: " << stdev << " ms.\n";
}

void encrypt_test()
{
	AES_KEY enc_key;

	timeval t1, t2;
    double elapsedTime;
	unsigned char hash[32];
	std::vector<double> v;

	AES_set_encrypt_key(aes_key, 256, &enc_key);
	for (int i = 0; i < KEY_GEN_REPEAT_TIME; i++) {
		// AES encryption of block
    	gettimeofday(&t1, NULL);
		AES_encrypt(block, buf, &enc_key);
		gettimeofday(&t2, NULL);

		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
	}

	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	// cout << "Time to generate a RSA key pair is: " << elapsedTime/KEY_GEN_REPEAT_TIME << " ms.\n";
	cout << "AES 256 encryption mean is: " << mean << " ms, std dev is: " << stdev << " ms.\n";
}

void decrypt_test()
{
	AES_KEY dec_key;

	timeval t1, t2;
    double elapsedTime;
	unsigned char hash[32];
	std::vector<double> v;

	AES_set_encrypt_key(aes_key, 256, &dec_key);
	for (int i = 0; i < KEY_GEN_REPEAT_TIME; i++) {
		// AES encryption of block
    	gettimeofday(&t1, NULL);
		AES_decrypt(block, buf, &dec_key);
		gettimeofday(&t2, NULL);

		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
	}

	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	// cout << "Time to generate a RSA key pair is: " << elapsedTime/KEY_GEN_REPEAT_TIME << " ms.\n";
	cout << "AES 256 encryption mean is: " << mean << " ms, std dev is: " << stdev << " ms.\n";
}

unsigned int
sign_test(RSA *rsa)
{
	timeval t1, t2;
    double elapsedTime;
	unsigned char hash[32];
	std::vector<double> v;
	unsigned int len = 2 * BLOCK_SIZE;

	for (int i = 0; i < KEY_GEN_REPEAT_TIME; i++) {
		// RSA sign of block
    	gettimeofday(&t1, NULL);
		RSA_sign(NID_sha1, block, BLOCK_SIZE, buf, &len, rsa);
		gettimeofday(&t2, NULL);

		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
	}

	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	// cout << "Time to generate a RSA key pair is: " << elapsedTime/KEY_GEN_REPEAT_TIME << " ms.\n";
	cout << "RSA sign mean is: " << mean << " ms, std dev is: " << stdev << " ms.\n";
	return len;
}

void verify_test(RSA *rsa, unsigned int len)
{
	timeval t1, t2;
    double elapsedTime;
	unsigned char hash[32];
	std::vector<double> v;

	for (int i = 0; i < KEY_GEN_REPEAT_TIME; i++) {
		// RSA sign of block
    	gettimeofday(&t1, NULL);
		RSA_verify(NID_sha1, block, BLOCK_SIZE, buf, len, rsa);
		gettimeofday(&t2, NULL);

		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
	}

	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	// cout << "Time to generate a RSA key pair is: " << elapsedTime/KEY_GEN_REPEAT_TIME << " ms.\n";
	cout << "RSA verify mean is: " << mean << " ms, std dev is: " << stdev << " ms.\n";
}

int main()
{
    timeval t1, t2;
    double elapsedTime;

	rsa_gen_time();

    // micro-benchmark to test key rotation time
	RSA *rsa = NULL;
	rsa = RSA_new();

	// generate a 1024-bit long RSA public-private key pair
	//rsa = RSA_generate_key(1024, 0x10001, NULL, NULL);
    BIGNUM *wggkey = BN_new();
    BN_set_word(wggkey,0x10001);
    RSA_generate_key_ex(rsa,1024,wggkey,NULL);
    BN_free(wggkey);
    // generate a 256-bit AES symmetric encryption key
    //BIGNUM *key = BN_generate_prime(NULL, 256, false, NULL, NULL, NULL, NULL);
    BIGNUM *key=BN_new();
    BN_generate_prime_ex(key,256,false,NULL,NULL,NULL);

    // double buffer size in case overflow
    timeval t3, t4;
	std::vector<double> v;
    for (int i = 0; i < KEY_ROTATION_REPEAT_TIME; i++) {
        // RSA_private_encrypt(11, key, encrypted, rsa, RSA_PKCS1_PADDING);
        BIGNUM *ret = BN_new();
        BN_CTX *ctx = BN_CTX_new();
    	gettimeofday(&t3, NULL);
        BN_mod_exp(ret, key, rsa->d, rsa->n, ctx);
    	gettimeofday(&t4, NULL);
        BN_free(ret);
        BN_CTX_free(ctx);
    	elapsedTime = (t4.tv_sec - t3.tv_sec) * 1000.0;      // sec to ms
    	elapsedTime += (t4.tv_usec - t3.tv_usec) / 1000.0;   // us to ms
		v.push_back(elapsedTime);
    }
    BN_free(key);
    // compute and print the elapsed time in millisec
    // cout << "Time to rotate a key 100 times is: " << elapsedTime << " ms.\n";
    
	// compute and print the elapsed time in millisec
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
	double mean = sum / v.size();

	double sq_sum = std::inner_product(v.begin(), v.end(), v.begin(), 0.0);
	double stdev = std::sqrt(sq_sum / v.size() - mean * mean);
	cout << "key rotation mean: " << mean << " ms, std dev: " << stdev << " ms.\n";

	// generate random 4KB data
	RAND_bytes(block, BLOCK_SIZE);

	hash_test();
	encrypt_test();
	decrypt_test();
	unsigned int len = sign_test(rsa);
	verify_test(rsa, len);
    return 0;
}
