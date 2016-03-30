#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "rijndael.h"

#define KEYBITS 128

//get filenode (%d) fileStat.st_ino

int main (int argc, char ** argv){
	char * option;
	char * key;
	char keyPart1[9];
	char keyPart2[9];
	char * file;
	int i, j;
  int fileId;
	int k0, k1;
	int statSuccess;
	struct stat fileStat;
	mode_t mode;

	if (argc < 3){
		fprintf (stderr, "Usage %s <-e/-d> <key> <file>\n", argv[0]);
		return 1;
	}

	option = argv[1];
	key = argv[2];
	file = argv[3];
	
  //split key into 2.
	for (i = 0; i < 16; i++){
		if (i < 8){
			keyPart2[i] = key[i];
		} else {
			keyPart1[i - 8] = key[i];
		}
	}

	keyPart1[8] = '\0';
	keyPart2[8] = '\0';

  //encrypt
	if (option[0] == '-' && option[1] == 'e'){
		if (statSuccess = stat(file, &fileStat))
            printf(stderr, "Couldn't stat.\n");
        
	 	//check sticky bit
	 	mode = fileStat.st_mode & 07777;
	    if (!(fileStat.st_mode & S_ISTXT)){
        fileId = fileStat.st_ino;
	    	readyForEncryption(keyPart1, keyPart2, file, fileId);
        //set sticky bit to on.
        mode |= S_ISTXT;
        chmod (file, mode);
	    }
	}

  //decrypt
	if (option[0] == '-' && option[1] == 'd'){
		statSuccess = stat(file, &fileStat);

		//check sticky bit
		mode = fileStat.st_mode & 07777;
		if (fileStat.st_mode & S_ISTXT){
      //set sticky bit to off.
      mode &= ~S_ISTXT;
      chmod (file, mode);
      fileId = fileStat.st_ino;
	    readyForEncryption(keyPart1, keyPart2, file, fileId);
		}
	}
}

int hexvalue (char c)
{
  if (c >= '0' && c <= '9') {
    return (c - '0');
  } else if (c >= 'a' && c <= 'f') {
    return (10 + c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    return (10 + c - 'A');
  } else {
    fprintf (stderr, "ERROR: key digit %c isn't a hex digit!\n", c);
    exit (-1);
  }
}

void
getpassword (const char *password, unsigned char *key, int keylen)
{
  int		i;

  for (i = 0; i < keylen; i++) {
    if (*password == '\0') {
      key[i] = 0;
    } else {
      /* Add the first of two digits to the current key value */
      key[i] = hexvalue (*(password++)) << 4;
      /* If there's a second digit at this position, add it */
      if (*password != '\0') {
	key[i] |= hexvalue (*(password++));
      }
    }
  }
}

void readyForEncryption(char * keyPart1, char * keyPart2,
                        char * filename, int fileId) {
  unsigned long rk[RKLENGTH(KEYBITS)];	/* round key */
  unsigned char key[KEYLENGTH(KEYBITS)];/* cipher key */
  char	buf[100];
  int i, nbytes, nwritten , ctr;
  int totalbytes;
  int	k0, k1;
  //int fileId = 0x1234;			/* fake (in this example) */
  int nrounds;					/* # of Rijndael rounds */
  char *password;				/* supplied (ASCII) password */
  int	fd;
  unsigned char filedata[16];
  unsigned char ciphertext[16];
  unsigned char ctrvalue[16];


  bzero (key, sizeof (key));
  k0 = strtol (keyPart1, NULL, 0);
  k1 = strtol (keyPart2, NULL, 0);
  bcopy (&k0, &(key[0]), sizeof (k0));
  bcopy (&k1, &(key[sizeof(k0)]), sizeof (k1));

  /* Print the key, just in case */
  for (i = 0; i < sizeof (key); i++) {
    sprintf (buf+2*i, "%02x", key[sizeof(key)-i-1]);
  }
  fprintf (stderr, "KEY: %s\n", buf);

  /*
   * Initialize the Rijndael algorithm.  The round key is initialized by this
   * call from the values passed in key and KEYBITS.
   */
  nrounds = rijndaelSetupEncrypt(rk, key, KEYBITS);

  /* fileID goes into bytes 8-11 of the ctrvalue */
  bcopy (&fileId, &(ctrvalue[8]), sizeof (fileId));

  /* This loop reads 16 bytes from the file, XORs it with the encrypted
     CTR value, and then writes it back to the file at the same position.
     Note that CTR encryption is nice because the same algorithm does
     encryption and decryption.  In other words, if you run this program
     twice, it will first encrypt and then decrypt the file.
  */
  for (ctr = 0, totalbytes = 0, nbytes = 0; /* loop forever */; ctr++)
  {
    /* Read 16 bytes (128 bits, the blocksize) from the file */
    filedata = ;/buffer;
    nbytes += 16;
    
    /* Set up the CTR value to be encrypted */
    bcopy (&ctr, &(ctrvalue[0]), sizeof (ctr));

    /* Call the encryption routine to encrypt the CTR value */
    rijndaelEncrypt(rk, nrounds, ctrvalue, ciphertext);

    /* XOR the result into the file data */
    for (i = 0; i < nbytes; i++) {
      filedata[i] ^= ciphertext[i];
    }

    /* Write the result back to the file */
    //write back to buffer here

    /* Increment the total bytes written */
    totalbytes += nbytes;
  }
}

