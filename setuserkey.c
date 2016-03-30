#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX 128

int main (){
	char pw[MAX];
	unsigned char hash[SHA_DIGEST_LENGTH];
	size_t length;
	unsigned char key0[5];
	unsigned char key1[5];
	int k0, k1;
	int i,f;
	char * p;

	printf("Enter passphrase: ");
	scanf("%s", pw);
	length = sizeof(pw);

	SHA1(pw, length, hash);

	for (i = 0; i < 8; i++){
		if (i < 4){
			key0[i] = hash[i];
		} else {
			key1[i-4] = hash[i];
		}
	}

  	syscall(546, *(unsigned int *)key0, *(unsigned int *) key1);
}
