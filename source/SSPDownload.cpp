#include "ITLSSPProc.h"
#include "itl_types.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <chrono>

#include "Random.h"
#include "Encryption.h"
#include "SSPComs.h"
#include "serialfunc.h"
#include "ssp_defines.h"

namespace {
    bool g_bDownload_in_progress{ false };
    uint32_t download_block{ 0 };
    uint32_t download_blocks_count{ 1 };

}
/*
Name:   _downloadDataToTarget
Inputs:
    char * data: The array of data you wish to download
    long data_length: length of data to download
    char * port: The name of the port to use (eg /dev/ttyUSB0 for usb serial, /dev/ttyS0 for com port 1)
    unsigned char sspAddress: The ssp address to download to
Return:
    If the value is less than 0x100000 it is the number of blocks to be downloaded.
    On an error, the value will be greater than 0x100000, and one of the following
    Failure:
    OPEN_FILE_ERROR					0x100001
    READ_FILE_ERROR					0x100002
    NOT_ITL_FILE					0x100003
    PORT_OPEN_FAIL					0x100004
    SYNC_CONNECTION_FAIL			0x100005
    SECURITY_PROTECTED_FILE			0x100006
    DATA_TRANSFER_FAIL				0x100010
    PROG_COMMAND_FAIL				0x100011
    HEADER_FAIL						0x100012
    PROG_STATUS_FAIL				0x100013
    PROG_RESET_FAIL					0x100014
    DOWNLOAD_NOT_ALLOWED			0x100015
    HI_TRANSFER_SPEED_FAIL			0x100016
Notes:
    The download is done in a separate thread - see GetDownloadStatus() for information about its progress
    Only one download operation may be in progress at once.
*/
uint32_t _downloadDataToTarget(const unsigned char* data, const uint32_t dlength, const char * cPort, const unsigned char sspAddress, const unsigned long long key)
{

	int i;
    uint32_t numCurBytes;
	unsigned short dBlockSize;
    std::unique_ptr< ITL_FILE_DOWNLOAD > itlFile;
    itlFile.reset( new ITL_FILE_DOWNLOAD );

    SSP_COMMAND sspC;
    if( g_bDownload_in_progress ) {
        return PORT_OPEN_FAIL;
    }

    std::copy( data, data + dlength, std::back_inserter( itlFile->data ) );

    // check for ITL BV/SH type file
    if (itlFile->data[0] == 'I' && itlFile->data[1] == 'T' && itlFile->data[2] == 'L') {

		 numCurBytes = 0;
		 for(i = 0; i <4; i++){
            numCurBytes += (uint32_t)itlFile->data[17 + i] << (8*(3-i));
		 }
		  //get the block size from header
         dBlockSize = (256*(unsigned short)itlFile->data[0x3e]) + (unsigned short)itlFile->data[0x3f];
		// correct for NV9 type
		 if(dBlockSize == 0) dBlockSize = 4096;

          itlFile->NumberOfBlocks = numCurBytes / dBlockSize;
          if(numCurBytes % dBlockSize != 0) itlFile->NumberOfBlocks += 1;

          download_blocks_count = itlFile->NumberOfBlocks;
    } else {
		return NOT_ITL_FILE;
	}

	/* check target connection   */
	sspC.Timeout = 1000;
	sspC.BaudRate = 9600;
	sspC.RetryLevel = 2;
	sspC.SSPAddress = sspAddress;
    itlFile->SSPAddress = sspAddress;
    strcpy( itlFile->portname, cPort );
    itlFile->port = OpenSSPPort(cPort);
    if( !itlFile->port ) {
        return PORT_OPEN_FAIL;
    }
	sspC.EncryptionStatus = 0;
	sspC.CommandDataLength = 1;
	sspC.CommandData[0]  = SSP_CMD_SYNC;

    if( SSPSendCommand( itlFile->port, &sspC ) == 0 ){
        CloseSSPPort( itlFile->port );
        return SYNC_CONNECTION_FAIL;
	}
	if(sspC.ResponseData[0] != SSP_RESPONSE_OK){
        CloseSSPPort( itlFile->port );
		return SYNC_CONNECTION_FAIL;
	}
	if (key > 0)
	{
        if (NegotiateSSPEncryption( itlFile->port, sspAddress, &itlFile->Key ) == 0 )
        {
            CloseSSPPort( itlFile->port );
            return SYNC_CONNECTION_FAIL;
        }
        itlFile->EncryptionStatus = 1;
        itlFile->Key.FixedKey = key;
	}

    return __downloadITLTarget( std::move( itlFile ) );
}

/*
Name: DownloadFileToTarget
Inputs:
    char *file: The full path of the file to download
    char * port: The name of the port to use (eg /dev/ttyUSB0 for usb serial, /dev/ttyS0 for com port 1)
    unsigned char sspAddress: The ssp address to download to
Return:
    If the value is less than 0x100000 it is the number of blocks to be downloaded.
    On an error, the value will be greater than 0x100000, and one of the following
    Failure:
    OPEN_FILE_ERROR					0x100001
    READ_FILE_ERROR					0x100002
    NOT_ITL_FILE					0x100003
    PORT_OPEN_FAIL					0x100004
    SYNC_CONNECTION_FAIL			0x100005
    SECURITY_PROTECTED_FILE			0x100006
    DATA_TRANSFER_FAIL				0x100010
    PROG_COMMAND_FAIL				0x100011
    HEADER_FAIL						0x100012
    PROG_STATUS_FAIL				0x100013
    PROG_RESET_FAIL					0x100014
    DOWNLOAD_NOT_ALLOWED			0x100015
    HI_TRANSFER_SPEED_FAIL			0x100016
Notes:
    The download is done in a separate thread - see GetDownloadStatus() for information about its progress.
    Only one download operation may be in progress at once.
*/
uint32_t DownloadFileToTarget(const char * file, const char * port, const unsigned char sspAddress,const unsigned long long key)
{
	FILE * f;
    uint32_t data_length = 0;
	unsigned char * data;
	f = fopen(file,"rb");

    if( nullptr == f ) {
	    return OPEN_FILE_ERROR;
    }

    //get length of file
	fseek(f, 0 , SEEK_END);
	data_length = ftell(f);
	rewind(f);
    data = reinterpret_cast< unsigned char * >( ::malloc(data_length) );
    fread(data,1,data_length,f);
    fclose(f);
    auto i = _downloadDataToTarget( data,data_length,port,sspAddress,key );
    free(data);
    return i;
}

uint8_t _read_single_byte_reply( ITL_FILE_DOWNLOAD* itlFile, const uint32_t timeout)
{
    auto result = itlFile->port->WaitForIncomingData( 1, timeout, false );
    if( result.first == true ) {
        return result.second[ 0 ];
    }

    return -1;
}

unsigned char _send_download_command( const unsigned char* data, const uint32_t length, const unsigned char expected_response, ITL_FILE_DOWNLOAD * itlFile)
{
    unsigned char buffer;

    WriteData( data, length, itlFile->port, false );

    buffer = _read_single_byte_reply( itlFile, 5000 );

    if( buffer == expected_response ) {
        return 1;
    }
    return 0;
}

#define RAM_DWNL_BLOCK_SIZE				128
uint32_t ___download_ram_file(ITL_FILE_DOWNLOAD * itlFile, SSP_COMMAND * sspC)
{
    uint32_t i;
    uint32_t baud;
    unsigned char buffer;
    uint32_t numRamBlocks;
    //initiate communication
	sspC->CommandDataLength = 2;
	sspC->CommandData[0] = SSP_CMD_PROGRAM;
	sspC->CommandData[1] = SSP_PROGRAM_RAM;

	if (SSPSendCommand(itlFile->port,sspC) == 0)
        return PROG_COMMAND_FAIL;
    if (sspC->ResponseData[0] != SSP_RESPONSE_OK)
        return PROG_COMMAND_FAIL;

    //calculate block size
    itlFile->dwnlBlockSize = ((unsigned short)sspC->ResponseData[1]) + (((unsigned short)sspC->ResponseData[2])<<8);

    sspC->EncryptionStatus = 0;
    sspC->CommandDataLength = 128;
    for (i = 0; i < 128; ++i)
        sspC->CommandData[i] = itlFile->data[i];

    SSPSendCommand(itlFile->port,sspC);
    if (sspC->ResponseData[ 0] == SSP_RESPONSE_HEADER_FAILURE)
        return HEADER_FAIL;
    else if (sspC->ResponseData[0] != SSP_RESPONSE_OK)
        return DATA_TRANSFER_FAIL;

    baud = 38400;
    if((itlFile->data[5] != 0x9) && (itlFile->data[5] != 0xA)){ //NV9/10
		baud = 0;
		for(i = 0; i < 4; i++){
            baud += (long)itlFile->data[68 + i] << ((3- i)  * 8);
		}
		if(baud == 0) baud = 38400;
	}
	SetBaud(itlFile->port,baud);
    itlFile->baud = baud;

    usleep(500000);

    numRamBlocks = itlFile->NumberOfRamBytes/RAM_DWNL_BLOCK_SIZE;

    for( i = 0; i < numRamBlocks; i++ ) {

        // Clear rx accumulator before writing the first block
        WriteData( &itlFile->data[ 128 + ( i * RAM_DWNL_BLOCK_SIZE ) ], RAM_DWNL_BLOCK_SIZE, itlFile->port, i == 0 );
	}

    if( ( itlFile->NumberOfRamBytes % RAM_DWNL_BLOCK_SIZE ) !=  0 ) {
        WriteData( &itlFile->data[ 128 + ( i * RAM_DWNL_BLOCK_SIZE ) ], itlFile->NumberOfRamBytes % RAM_DWNL_BLOCK_SIZE, itlFile->port, false );
    }

    buffer = _read_single_byte_reply( itlFile, 500 );
    itlFile->port->StopThread();

    // check checksum
    if (itlFile->data[ 0x10 ] != buffer) {
        return DATA_TRANSFER_FAIL;
    }

    CloseSSPPort( itlFile->port );

	return DOWNLOAD_COMPLETE;
}

#define ram_OK_ACK  0x32
uint32_t ___download_main_file( ITL_FILE_DOWNLOAD* itlFile)
{
    unsigned char chk;
    uint32_t cur_block;
    uint32_t i;
    uint32_t block_offset;

    CloseSSPPort( itlFile->port );

    sleep(5);

    itlFile->port = OpenSSPPort(itlFile->portname);
    if( !itlFile->port ) {
        return PORT_OPEN_FAIL;
    }
    SetBaud(itlFile->port,itlFile->baud);

    if (_send_download_command( &itlFile->data[6], 1, ram_OK_ACK, itlFile ) == 0)
        return DATA_TRANSFER_FAIL;

    if (_send_download_command( itlFile->data.data(), 128, ram_OK_ACK, itlFile ) == 0)
        return DATA_TRANSFER_FAIL;

    for (cur_block = 1; cur_block <= itlFile->NumberOfBlocks; ++cur_block)
    {
        block_offset = 128 + ((cur_block-1)*itlFile->dwnlBlockSize) + itlFile->NumberOfRamBytes;
        chk = 0;
        for(i = 0; i < itlFile->dwnlBlockSize; ++i) {
            chk ^= itlFile->data[block_offset + i];
        }
        WriteData( &itlFile->data[ block_offset ], itlFile->dwnlBlockSize, itlFile->port, false );
        if( _send_download_command( &chk, 1, chk, itlFile ) == 0 )
            return DATA_TRANSFER_FAIL;

        download_block = cur_block;
    }
    return DOWNLOAD_COMPLETE;
}

uint32_t __downloadITLTarget( std::unique_ptr< ITL_FILE_DOWNLOAD > itlFile )
{
	unsigned int i;
    uint32_t return_value;
	SSP_COMMAND sspC;

    download_block = 0;
    g_bDownload_in_progress = true;

    sspC.Timeout = 1000;
	sspC.BaudRate = 9600;
	sspC.RetryLevel = 2;
	sspC.SSPAddress = itlFile->SSPAddress;
	sspC.EncryptionStatus = 0;

    if (itlFile->EncryptionStatus)
    {
        sspC.EncryptionStatus = 1;
        sspC.Key = itlFile->Key;
    }

    //get the number of ram bytes to download
	itlFile->NumberOfRamBytes = 0;
    for( i = 0; i < 4; i++ ) {
        itlFile->NumberOfRamBytes += (uint32_t)itlFile->data[7 + i] << (8 * (3-i));
    }

    return_value = ___download_ram_file( itlFile.get(), &sspC );
    if( return_value == DOWNLOAD_COMPLETE ) {

        std::thread _abandoned{
            [ itlParam = std::move( itlFile ) ]
            {
                ___download_main_file( itlParam.get() );
                CloseSSPPort( itlParam->port );
                g_bDownload_in_progress = false;
                download_block = DOWNLOAD_COMPLETE;
            }
        };
        _abandoned.detach();
        return DOWNLOAD_STARTED;
    } else {
        CloseSSPPort( itlFile->port );
        itlFile.reset();

        g_bDownload_in_progress = false;
        download_block = return_value;
        return return_value;
    }
}

uint32_t GetDownloadStatus( void )
{
    return download_block;
}

uint32_t GetFwBlocksCount( void )
{
    return download_blocks_count;
}
