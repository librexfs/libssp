#include <cstdlib>
#include "ITLSSPProc.h"
#include "Random.h"
#include "Encryption.h"
#include "ssp_defines.h"
#include "SSPComs.h"

extern unsigned char download_in_progress;

#define VER_MAJ  1  // not > 255
#define VER_MIN	 1	// not > 255
#define VER_REV	 0	// not > 255

unsigned int encPktCount[MAX_SSP_PORT];
unsigned char sspSeq[MAX_SSP_PORT];

typedef enum{
	KEY_GENERATOR,
	KEY_MODULUS,
    KEY_HOST_INTER,
	KEY_HOST_RANDOM,
	KEY_SLAVE_INTER,
	KEY_SLAVE_RANDOM,
	KEY_HOST,
	KEY_SLAVE,
}SSP_KEY_INDEX;


int GetProcDLLVersion(unsigned char* ver)
{
	ver[0] = VER_MAJ;
	ver[1] = VER_MIN;
	ver[2] = VER_REV;

	return 1;

}


/*    DLL function call to generate host intermediate numbers to send to slave  */
int InitiateSSPHostKeys(SSP_KEYS *  keyArray, const unsigned char ssp_address)
{
	long long swap = 0;

	/* create the two random prime numbers  */
	keyArray->Generator = GeneratePrime();
	keyArray->Modulus = GeneratePrime();
	/* make sure Generator is larger than Modulus   */
	if (keyArray->Generator > keyArray->Modulus)
	{
		swap = keyArray->Generator;
		keyArray->Generator = keyArray->Modulus;
		keyArray->Modulus = swap;
	}


	if(CreateHostInterKey(reinterpret_cast<SSP_KEYS *>(reinterpret_cast<int *>(keyArray))) == -1)
		return 0;


	/* reset the apcket counter here for a successful key neg  */
	encPktCount[ssp_address] = 0;

	return 1;
}

/* creates the host encryption key   */
int CreateSSPHostEncryptionKey(SSP_KEYS* keyArray)
{
	keyArray->KeyHost = XpowYmodN(keyArray->SlaveInterKey,keyArray->HostRandom,keyArray->Modulus);

	return 1;
}

int EncryptSSPPacket(unsigned char ptNum,const unsigned char* dataIn, unsigned char* dataOut, const unsigned char* lengthIn,unsigned char* lengthOut, unsigned long long* key)
{
	#define FIXED_PACKET_LENGTH   7
	unsigned char pkLength,i,packLength = 0;
	unsigned short crc;
	unsigned char tmpData[255];


	pkLength = *lengthIn + FIXED_PACKET_LENGTH;

	/* find the length of packing data required */
	if(pkLength % C_MAX_KEY_LENGTH != 0){
		packLength = C_MAX_KEY_LENGTH - (pkLength % C_MAX_KEY_LENGTH);
	}
	pkLength += packLength;

	tmpData[0] = *lengthIn; /* the length of the data without packing */

	/* add in the encrypted packet count   */
	for(i = 0; i < 4; i++)
		tmpData[1 + i] = (unsigned char)((encPktCount[ptNum] >> (8*i) & 0xFF));


	for(i = 0; i < *lengthIn; i++)
		tmpData[i + 5] = dataIn[i];


	/* add random packing data  */
	for(i = 0; i < packLength; i++)
		tmpData[5 + *lengthIn + i] =  (unsigned char)(rand() % 255);
	/* add CRC to packet end   */

	crc = cal_crc_loop_CCITT_A(pkLength - 2,tmpData,CRC_SSP_SEED,CRC_SSP_POLY);

	tmpData[pkLength - 2] = (unsigned char)(crc & 0xFF);
	tmpData[pkLength - 1] = (unsigned char)((crc >> 8) & 0xFF);

	if (aes_encrypt(C_AES_MODE_ECB,
                    reinterpret_cast<const UINT8 *>(reinterpret_cast<const int *>((unsigned char *) key)), C_MAX_KEY_LENGTH, nullptr, 0,
                    reinterpret_cast<UINT8 *>(reinterpret_cast<int *>(tmpData)),
                    reinterpret_cast<UINT8 *>(reinterpret_cast<int *>(&dataOut[1])), pkLength) != E_AES_SUCCESS)
							return 0;

	pkLength++; /* increment as the final length will have an STEX command added   */
	*lengthOut = pkLength;
	dataOut[0] = SSP_STEX;

	encPktCount[ptNum]++;  /* increment the counter after a successful encrypted packet   */

	return 1;
}

 int  DecryptSSPPacket(const unsigned char* dataIn, const unsigned char* dataOut, const unsigned char* lengthIn,unsigned char* /* lengthOut */, unsigned long long* key)
{
	if (aes_decrypt(C_AES_MODE_ECB,
                    reinterpret_cast<const UINT8 *>(reinterpret_cast<const int *>((unsigned char *) key)), C_MAX_KEY_LENGTH, nullptr, 0,
                    reinterpret_cast<UINT8 *>((int *) dataOut), reinterpret_cast<UINT8 *>((int *) dataIn), *lengthIn) != E_AES_SUCCESS)
							return 0;

	return 1;
}

/* Creates a host intermediate key */
int CreateHostInterKey(SSP_KEYS * keyArray)
{

	if (keyArray->Generator ==0 || keyArray->Modulus ==0 )
		return -1;

	keyArray->HostRandom = (long long) (GenerateRandomNumber() % MAX_RANDOM_INTEGER);
	keyArray->HostInter = XpowYmodN(keyArray->Generator,keyArray->HostRandom,keyArray->Modulus );

	return 0;
}

void __attribute__ ((constructor)) my_init()
{
    int i;
    for(i = 0; i < MAX_SSP_PORT; i++){
		encPktCount[i] = 0;
		sspSeq[i] = 0x80;
	}
}

void __attribute__ ((destructor)) my_fini() {}

/*
Name: NegotiateSSPEncryption
Inputs:
    SSP_PORT The port handle (returned from OpenSSPPort) of the port to use
    char ssp_address: The ssp_address to negotiate on
    SSP_FULL_KEY * key: The ssp encryption key to be used
Return:
    1 on success
    0 on failure
Notes:
    Only the EncryptKey iin SSP_FULL_KEY will be set. The FixedKey needs to be set by the user
*/
int NegotiateSSPEncryption(const SSP_PORT_WP& port, const char ssp_address, SSP_FULL_KEY * key)
{
    SSP_KEYS temp_keys;
    SSP_COMMAND sspc;
    unsigned char i;
    // Setup initial host keys
    if (InitiateSSPHostKeys(&temp_keys,ssp_address) == 0)
        return 0;
    sspc.EncryptionStatus = 0;
    sspc.RetryLevel = 2;
    sspc.Timeout = 1000;
    sspc.SSPAddress = ssp_address;

    // Make sure we can talk to the unit
    sspc.CommandDataLength = 1;
    sspc.CommandData[0] = SSP_CMD_SYNC;
    SSPSendCommand(port,&sspc);
    if (sspc.ResponseData[0] != SSP_RESPONSE_OK)
        return 0;

    // Setup generator
    sspc.CommandDataLength = 9;
    sspc.CommandData[0] = SSP_CMD_SET_GENERATOR;
    for (i = 0; i < 8 ; ++i)
        sspc.CommandData[1+i] = (unsigned char)(temp_keys.Generator >> (i*8));
    //send the command
    SSPSendCommand(port,&sspc);
    if (sspc.ResponseData[0] != SSP_RESPONSE_OK)
        return 0;

    // Setup modulus
    sspc.CommandDataLength = 9;
    sspc.CommandData[0] = SSP_CMD_SET_MODULUS;
    for (i = 0; i < 8 ; ++i)
        sspc.CommandData[1+i] = (unsigned char)(temp_keys.Modulus >> (i*8));
    //send the command
    SSPSendCommand(port,&sspc);
    if (sspc.ResponseData[0] != SSP_RESPONSE_OK)
        return 0;

    // Swap keys
    sspc.CommandDataLength = 9;
    sspc.CommandData[0] = SSP_CMD_REQ_KEY_EXCHANGE;
    for (i = 0; i < 8 ; ++i)
        sspc.CommandData[1+i] = (unsigned char)(temp_keys.HostInter >> (i*8));
    // Send the command
    SSPSendCommand(port,&sspc);
    if (sspc.ResponseData[0] != SSP_RESPONSE_OK)
        return 0;

    // Read the slave key
    temp_keys.SlaveInterKey = 0;
    for (i = 0; i < 8 ; ++i)
        temp_keys.SlaveInterKey +=  ((long long)(sspc.ResponseData[1+i])) << (8*i);

    key->EncryptKey = temp_keys.KeyHost;
    return 1;
}

