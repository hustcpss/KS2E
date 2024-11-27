//Create time 2019/11/14
// Dongli Liu
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#define	RET_SUCCESS 1
#define AES_BLOCK_SIZE 16
#define SHA256_SIZE 32 // correct with sha256
#define SHA512_SIZE 64

unsigned char owner_key_1[AES_BLOCK_SIZE]={0};
unsigned char owner_key_2[AES_BLOCK_SIZE]={0};
unsigned char user_key_1[AES_BLOCK_SIZE]={0};
unsigned char user_key_2[AES_BLOCK_SIZE]={0};
unsigned char bot_str[SHA512_SIZE]={0};

static void _xor(unsigned char* a , unsigned char* b ,unsigned int len , unsigned char* c)
{
    for(int i =0 ; i< len ; i++)c[i] = a[i]^b[i];
        return;
}

int my_aes_encrypt(unsigned char *in , unsigned char *out , size_t len , unsigned char* key)
{

	if(!in||!key||!out)
	{
		printf("%s\n" , "invaid input");
		return -1;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv , 0 , AES_BLOCK_SIZE);

	AES_KEY aes;

	if(AES_set_encrypt_key((unsigned char*)key , 128 , &aes) < 0)
	{
		perror("AES_set_encrypt_key()");
		return 0;
	}

	AES_cbc_encrypt((unsigned char*)in , (unsigned char*)out , len , &aes , iv , AES_ENCRYPT);

	return len;
}
int my_aes_decrypt(unsigned char *in , unsigned char *out , size_t len  , unsigned char* key)
{
	if(!in||!key||!out)
	{

		return -1;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv , 0 , AES_BLOCK_SIZE);

	AES_KEY aes;
	if(AES_set_decrypt_key((unsigned char*)key , 128 , &aes) < 0)
	{
		perror("AES_set_decrypt_key()");
		return 0;
	}
	AES_cbc_encrypt((unsigned char*)in , (unsigned char*)out , len , &aes , iv , AES_DECRYPT);

	return len;
}
static PyObject* AESDecrypt(PyObject *self , PyObject *args)
{
	PyObject * ret;
	unsigned int key_len, cipher_len;
	unsigned char *cipher, *key;
	unsigned char plaintext[SHA256_SIZE]={0};
	if(!PyArg_ParseTuple(args , "y#y#" , &key, &key_len , &cipher, &cipher_len ))
    {
      return NULL;
    }

    clock_t t_start,t_end;
	t_start = clock();

	my_aes_decrypt(cipher,plaintext,SHA256_SIZE,key);

	t_end = clock();
    double dur = (double)(t_end-t_start);
 
    ret = (PyObject* )Py_BuildValue("ds#",dur/CLOCKS_PER_SEC,
    	 plaintext, strlen(plaintext)
    	 );

    return ret;
}

static PyObject* XortoNext (PyObject *self , PyObject *args)
{
	PyObject *ret;
	unsigned char F_2[SHA512_SIZE]={0}; unsigned int F_2_len;
	unsigned char I_2[SHA512_SIZE]={0}; unsigned int I_2_len;
	unsigned int J_len,R_len,I_len;
	unsigned char *J,*R,*I;

	if(!PyArg_ParseTuple(args , "y#y#y#" , &J ,&J_len, &R , &R_len , &I, &I_len))
    {
      return NULL;
    }

    clock_t t_start,t_end;
	t_start = clock();

    //H(J,R)
    memcpy(F_2,J,SHA256_SIZE);
    memcpy(F_2+SHA256_SIZE,R,SHA256_SIZE);
    SHA512(F_2,SHA512_SIZE, I_2);
    
    _xor(I_2 , I , SHA512_SIZE , I_2);

    t_end = clock();
    double dur = (double)(t_end-t_start);


    ret = (PyObject *)Py_BuildValue("dy#y#" ,dur/CLOCKS_PER_SEC, I_2 , SHA256_SIZE , I_2+SHA256_SIZE, SHA256_SIZE);

   	return ret;
}

static PyObject* Setup(PyObject *self , PyObject *args)
{
    PyObject * ret;

	clock_t t_start,t_end;
	t_start = clock();

    RAND_pseudo_bytes(owner_key_1,AES_BLOCK_SIZE);
    RAND_pseudo_bytes(owner_key_2,AES_BLOCK_SIZE);
    RAND_pseudo_bytes(user_key_1,AES_BLOCK_SIZE);
    RAND_pseudo_bytes(user_key_2,AES_BLOCK_SIZE);

	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject *)Py_BuildValue("dy#y#y#y#" , dur/CLOCKS_PER_SEC,owner_key_1,AES_BLOCK_SIZE,owner_key_2,AES_BLOCK_SIZE,user_key_1,AES_BLOCK_SIZE,user_key_2,AES_BLOCK_SIZE);

    return ret;
}

static PyObject* Restart(PyObject *self, PyObject *args)
{
	PyObject *ret;
	unsigned char *K1; unsigned int K1_len;
	unsigned char *K2; unsigned int K2_len;
	unsigned char *K3; unsigned int K3_len;
	unsigned char *K4; unsigned int K4_len;

	if(!PyArg_ParseTuple(args , "y#y#y#y#" , &K1 ,&K1_len,&K2,&K2_len, &K3 ,&K3_len ,&K4,&K4_len))
    {
      return NULL;
    }
	clock_t t_start,t_end;
    t_start = clock();

    memcpy(owner_key_1,K1,AES_BLOCK_SIZE);
    memcpy(owner_key_2,K2,AES_BLOCK_SIZE);
    memcpy(user_key_1,K3,AES_BLOCK_SIZE);
    memcpy(user_key_2,K4,AES_BLOCK_SIZE);

	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject *)Py_BuildValue("d" , dur/CLOCKS_PER_SEC);
	return ret;
}

static PyObject* Encrypt(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char L[SHA256_SIZE]={0}; unsigned int L_len;
    unsigned char L_w_prime[SHA256_SIZE]={0}; unsigned int L_w_prime_len;
    unsigned char J_w_prime[SHA256_SIZE]={0}; unsigned int J_w_prime_len;
    unsigned char I_w[SHA512_SIZE]={0}; unsigned int I_w_len;

    unsigned char L_id_prime[SHA256_SIZE]={0}; unsigned int L_id_prime_len;
    unsigned char J_id_prime[SHA256_SIZE]={0}; unsigned int J_id_prime_len;
    unsigned char I_id[SHA512_SIZE]={0}; unsigned int I_id_len;

    unsigned char F_2[SHA512_SIZE]={0}; unsigned int F_2_len;
    unsigned char R_w[SHA256_SIZE]={0};
    unsigned char R_id[SHA256_SIZE]={0};

    unsigned char keyword_bytes[SHA256_SIZE]={0};
    unsigned char fileid_bytes[SHA256_SIZE]={0};
    unsigned char last_keyword_bytes[SHA256_SIZE]={0};
    unsigned char last_fileid_bytes[SHA256_SIZE]={0};

    unsigned char keyword_fileid[SHA512_SIZE]={0};
    unsigned char last_keyword_fileid[SHA512_SIZE]={0};
    unsigned char keyword_last_fileid[SHA512_SIZE]={0};

    unsigned char C_w[SHA256_SIZE]={0};
    unsigned char C_id[SHA256_SIZE]={0};

    unsigned char *keyword,*fileid,*last_keyword,*last_fileid;


    if(!PyArg_ParseTuple(args , "ssss" , &keyword, &fileid, &last_keyword , &last_fileid ))
    {
      return NULL;
    }


		memcpy(keyword_bytes,keyword,strlen(keyword));
		memcpy(fileid_bytes,fileid,strlen(fileid));
		memcpy(last_keyword_bytes,last_keyword,strlen(last_keyword));
		memcpy(last_fileid_bytes,last_fileid,strlen(last_fileid));

	clock_t t_start,t_end;
	t_start = clock();
		memcpy(keyword_fileid,keyword_bytes,SHA256_SIZE);
		memcpy(keyword_fileid+SHA256_SIZE,fileid_bytes,SHA256_SIZE);
		//L
		HMAC(EVP_sha256(),owner_key_1,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,L , &L_len);
		//R_w
		RAND_pseudo_bytes(R_w,SHA256_SIZE);
		//R_id
		RAND_pseudo_bytes(R_id,SHA256_SIZE);
		//k_w,C_w
		HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
		my_aes_encrypt(fileid_bytes , C_w , SHA256_SIZE , F_2);
		//k_id,C_id
		HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, fileid_bytes, SHA256_SIZE ,F_2 , &F_2_len);
		my_aes_encrypt(keyword_bytes , C_id , SHA256_SIZE , F_2);

		if(last_fileid_bytes[0]==0)// id is bot bot is 0 not '0'
		{

			HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
			memcpy(F_2+SHA256_SIZE,R_w,SHA256_SIZE);
			SHA512(F_2,SHA512_SIZE, I_w);

		}
		else
		{
			//L_w^prime
			memcpy(keyword_last_fileid,keyword_bytes,SHA256_SIZE);
			memcpy(keyword_last_fileid+SHA256_SIZE,last_fileid_bytes,SHA256_SIZE);
			HMAC(EVP_sha256(),owner_key_1,AES_BLOCK_SIZE, keyword_last_fileid, SHA512_SIZE ,L_w_prime , &L_w_prime_len);
			//J_w^prime
			HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE,keyword_last_fileid, SHA512_SIZE,J_w_prime,&J_w_prime_len);

			HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
			memcpy(F_2+SHA256_SIZE,R_w,SHA256_SIZE);
			SHA512(F_2,SHA512_SIZE, I_w);

			_xor(I_w,L_w_prime,SHA256_SIZE,I_w);
			_xor(I_w+SHA256_SIZE,J_w_prime,SHA256_SIZE,I_w+SHA256_SIZE);
		}

		if(last_keyword_bytes[0]==0)// w is bot bot is 0 not '0'
		{

			HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
			memcpy(F_2+SHA256_SIZE,R_id,SHA256_SIZE);
			SHA512(F_2,SHA512_SIZE, I_id);
		}
		else
		{
			//L_id^prime
			memcpy(last_keyword_fileid,last_keyword_bytes,SHA256_SIZE);
			memcpy(last_keyword_fileid+SHA256_SIZE,fileid_bytes,SHA256_SIZE);
			HMAC(EVP_sha256(),owner_key_1,AES_BLOCK_SIZE, last_keyword_fileid, SHA512_SIZE ,L_id_prime , &L_id_prime_len);
			//J_id^prime
			HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE,last_keyword_fileid,  SHA512_SIZE,J_id_prime,&J_id_prime_len);

			HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
			memcpy(F_2+SHA256_SIZE,R_id,SHA256_SIZE);
			SHA512(F_2,SHA512_SIZE, I_id);

			_xor(I_id,L_id_prime,SHA256_SIZE,I_id);
			_xor(I_id+SHA256_SIZE,J_id_prime,SHA256_SIZE,I_id+SHA256_SIZE);
		}

	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject* )Py_BuildValue("dy#y#y#y#y#y#y#" , dur/CLOCKS_PER_SEC , 
    	 L , SHA256_SIZE,
    	 I_w , SHA512_SIZE,
    	 R_w, SHA256_SIZE, 
    	 C_w, SHA256_SIZE,
    	 I_id, SHA512_SIZE,
    	 R_id, SHA256_SIZE,
    	 C_id, SHA256_SIZE
    	 );

    return ret;
}

static PyObject* OwnerKeyTrapdoor(PyObject *self , PyObject *args)
{

	unsigned char L_w[SHA256_SIZE]={0}; unsigned int L_w_len;
    unsigned char J_w[SHA256_SIZE]={0}; unsigned int J_w_len;

    unsigned char keyword_bytes[SHA256_SIZE]={0};
    unsigned char fileid_bytes[SHA256_SIZE]={0};
    unsigned char keyword_fileid[SHA512_SIZE]={0};

    unsigned char *keyword,*fileid;
    PyObject *ret;

    if(!PyArg_ParseTuple(args , "ss" , &keyword ,  &fileid))
    {
      return NULL;
    }

    memcpy(keyword_bytes,keyword,strlen(keyword));
    memcpy(fileid_bytes,fileid,strlen(fileid));


    clock_t t_start,t_end;
	t_start = clock();

	memcpy(keyword_fileid,keyword_bytes,SHA256_SIZE);
	memcpy(keyword_fileid+SHA256_SIZE,fileid_bytes,SHA256_SIZE);

	//L_w
	HMAC(EVP_sha256(),owner_key_1,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,L_w , &L_w_len);
	//J_w
	HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,J_w , &J_w_len);


	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject* )Py_BuildValue("dy#y#" , dur/CLOCKS_PER_SEC , 
    	L_w, SHA256_SIZE,
    	J_w, SHA256_SIZE
    	);

    return ret;
}

static PyObject* UserKeyTrapdoor(PyObject *self , PyObject *args)
{

	unsigned char L_w[SHA256_SIZE]={0}; unsigned int L_w_len;
    unsigned char J_w[SHA256_SIZE]={0}; unsigned int J_w_len;

    unsigned char keyword_bytes[SHA256_SIZE]={0};
    unsigned char fileid_bytes[SHA256_SIZE]={0};
    unsigned char keyword_fileid[SHA512_SIZE]={0};

    unsigned char *keyword,*fileid;
    PyObject *ret;

    if(!PyArg_ParseTuple(args , "ss" , &keyword ,  &fileid))
    {
      return NULL;
    }

    memcpy(keyword_bytes,keyword,strlen(keyword));
    memcpy(fileid_bytes,fileid,strlen(fileid));


    clock_t t_start,t_end;
	t_start = clock();

	memcpy(keyword_fileid,keyword_bytes,SHA256_SIZE);
	memcpy(keyword_fileid+SHA256_SIZE,fileid_bytes,SHA256_SIZE);

	//L_w
	HMAC(EVP_sha256(),user_key_1,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,L_w , &L_w_len);
	//J_w
	HMAC(EVP_sha256(),user_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,J_w , &J_w_len);


	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject* )Py_BuildValue("dy#y#" , dur/CLOCKS_PER_SEC , 
    	L_w, SHA256_SIZE,
    	J_w, SHA256_SIZE
    	);

    return ret;
}

static PyObject* Derivedkey(PyObject *self , PyObject *args)
{
    PyObject *ret;

    unsigned char fileid_bytes[SHA256_SIZE]={0};
    unsigned char keyword_bytes[SHA256_SIZE]={0};
    unsigned char keyword_fileid[SHA512_SIZE]={0};

    unsigned char L_id[SHA256_SIZE]={0}; unsigned int L_id_len;
    unsigned char J_id[SHA256_SIZE]={0}; unsigned int J_id_len;
    unsigned char k_id[SHA256_SIZE]={0}; unsigned int k_id_len;

    unsigned char *fileid,*keyword;

	if(!PyArg_ParseTuple(args , "ss"  , &keyword ,&fileid))
    {
      return NULL;
    }
    memcpy(keyword_bytes,keyword,strlen(keyword));
    memcpy(fileid_bytes,fileid,strlen(fileid));

    clock_t t_start,t_end;
	t_start = clock();

	
	memcpy(keyword_fileid,keyword_bytes,SHA256_SIZE);
	memcpy(keyword_fileid+SHA256_SIZE,fileid_bytes,SHA256_SIZE);

	//L_id
	HMAC(EVP_sha256(),owner_key_1,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,L_id , &L_id_len);
	//J_id
	HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,J_id , &J_id_len);
	//k_id
	HMAC(EVP_sha256(),owner_key_2,AES_BLOCK_SIZE, fileid_bytes, SHA256_SIZE ,k_id , &k_id_len);

	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject* )Py_BuildValue("dy#y#y#" , dur/CLOCKS_PER_SEC , 
    	 L_id , SHA256_SIZE,
    	 J_id , SHA256_SIZE, 
    	 k_id, k_id_len
    	);
    return ret;
}


static PyObject* Derive(PyObject *self , PyObject *args)
{
    PyObject *ret;
  
    unsigned char L[SHA256_SIZE]={0}; unsigned int L_len;
    unsigned char L_w_prime[SHA256_SIZE]={0}; unsigned int L_w_prime_len;
    unsigned char J_w_prime[SHA256_SIZE]={0}; unsigned int J_w_prime_len;
    unsigned char I_w[SHA512_SIZE]={0}; unsigned int I_w_len;

    unsigned char F_2[SHA512_SIZE]={0}; unsigned int F_2_len;
    unsigned char R_w[SHA256_SIZE]={0};

    unsigned char keyword_bytes[SHA256_SIZE]={0};
    unsigned char fileid_bytes[SHA256_SIZE]={0};

    unsigned char last_fileid_bytes[SHA256_SIZE]={0};

    unsigned char keyword_fileid[SHA512_SIZE]={0};

    unsigned char keyword_last_fileid[SHA512_SIZE]={0};

    unsigned char C_w[SHA256_SIZE]={0};

    unsigned char *keyword,*fileid,*last_fileid;

    if(!PyArg_ParseTuple(args , "sss" , &keyword, &fileid , &last_fileid ))
    {
      return NULL;
    }

	memcpy(keyword_bytes,keyword,strlen(keyword));
	memcpy(fileid_bytes,fileid,strlen(fileid));
	memcpy(last_fileid_bytes,last_fileid,strlen(last_fileid));

    clock_t t_start,t_end;
	t_start = clock();

	memcpy(keyword_fileid,keyword_bytes,SHA256_SIZE);
	memcpy(keyword_fileid+SHA256_SIZE,fileid_bytes,SHA256_SIZE);
	//L
	HMAC(EVP_sha256(),user_key_1,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,L , &L_len);
	//R_w
	RAND_pseudo_bytes(R_w,SHA256_SIZE);
	//k_w,C_w
	HMAC(EVP_sha256(),user_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
	my_aes_encrypt(fileid_bytes , C_w , SHA256_SIZE , F_2);

	if(last_fileid[0]==0)// id is bot bot is 0 not '0'
		{

			HMAC(EVP_sha256(),user_key_2,AES_BLOCK_SIZE, keyword_fileid, SHA512_SIZE ,F_2 , &F_2_len);
			memcpy(F_2+SHA256_SIZE,R_w,SHA256_SIZE);
			SHA512(F_2,SHA512_SIZE, I_w);
		}
		else
		{
			//L_w^prime
			memcpy(keyword_last_fileid,keyword_bytes,SHA256_SIZE);
			memcpy(keyword_last_fileid+SHA256_SIZE,last_fileid_bytes,SHA256_SIZE);

			HMAC(EVP_sha256(),user_key_1,AES_BLOCK_SIZE,keyword_last_fileid,SHA512_SIZE,L_w_prime,&L_w_prime_len);
			//J_w^prime
			HMAC(EVP_sha256(),user_key_2,AES_BLOCK_SIZE,keyword_last_fileid,SHA512_SIZE,J_w_prime,&J_w_prime_len);

			HMAC(EVP_sha256(),user_key_2,AES_BLOCK_SIZE,keyword_fileid,SHA512_SIZE ,F_2 , &F_2_len);
			memcpy(F_2+SHA256_SIZE,R_w,SHA256_SIZE);
			SHA512(F_2,SHA512_SIZE, I_w);

			_xor(I_w,L_w_prime,SHA256_SIZE,I_w);
			_xor(I_w+SHA256_SIZE,J_w_prime,SHA256_SIZE,I_w+SHA256_SIZE);
		}


	t_end = clock();
    double dur = (double)(t_end-t_start);

    ret = (PyObject* )Py_BuildValue("dy#y#y#y#" , dur/CLOCKS_PER_SEC , 
    	 L , SHA256_SIZE, 
    	 I_w , SHA512_SIZE,
    	 R_w , SHA256_SIZE,
    	 C_w , SHA256_SIZE
    	 );

    return ret;
}


static PyMethodDef
LiuB_methods[] = {
    {"Setup" , Setup, METH_VARARGS},
    {"Encrypt" , Encrypt , METH_VARARGS},
    {"Derive" , Derive , METH_VARARGS},
    {"Derivedkey", Derivedkey , METH_VARARGS},
    {"OwnerKeyTrapdoor" , OwnerKeyTrapdoor, METH_VARARGS},
    {"UserKeyTrapdoor" , UserKeyTrapdoor, METH_VARARGS},
    {"AESDecrypt" , AESDecrypt,METH_VARARGS},
    {"Restart", Restart, METH_VARARGS},
    {"XortoNext",XortoNext,METH_VARARGS},
    {0, 0, 0},
	};

static struct PyModuleDef
LiuB_mod = {
    PyModuleDef_HEAD_INIT,
    "LiuB_mod",
    "",
    -1,
    LiuB_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_LiuB_mod(void)
{
    return PyModule_Create(&LiuB_mod);
}
