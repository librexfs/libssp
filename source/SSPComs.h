#pragma once

#define NOMANGLE

#include "itl_types.h"
#include "ssp_defines.h"
#include <functional>


// Setting the outer logger for the comm subsystem
using _itl_ssp_logger_functor_t = std::function< void ( const std::wstring& strLogMessage, bool bExt ) >;
void _itl_ssp_set_logger( _itl_ssp_logger_functor_t fn );
void _itl_ssp_set_last_time_sent_cmd( void );

#define MAX_SSP_PORT 200

#define NO_ENCRYPTION 0
#define ENCRYPTION_SET 1

struct SSspChannel
{
    uint8_t nValue{0};
    uint32_t nNominal{0};
    std::wstring strCode;
};

typedef struct{
	unsigned long long FixedKey;
	unsigned long long EncryptKey;
}SSP_FULL_KEY;

typedef struct{
	unsigned short packetTime;
	unsigned char PacketLength;
	unsigned char PacketData[255];
}SSP_PACKET;

typedef struct{
	SSP_FULL_KEY Key;
	unsigned long BaudRate;
	unsigned long Timeout;
	unsigned char PortNumber;
	unsigned char SSPAddress;
	unsigned char RetryLevel;
	unsigned char EncryptionStatus;
	unsigned char CommandDataLength;
	unsigned char CommandData[255];
	unsigned char ResponseStatus;
	unsigned char ResponseDataLength;
	unsigned char ResponseData[255];
	unsigned char IgnoreError;
}SSP_COMMAND;

typedef struct{
	unsigned char txData[255];
	unsigned char txPtr;
	unsigned char rxData[255];
	unsigned char rxPtr;
	unsigned char txBufferLength;
	unsigned char rxBufferLength;
	unsigned char SSPAddress;
	unsigned char NewResponse;
	unsigned char CheckStuff;
}SSP_TX_RX_PACKET;

typedef struct{
    long long Generator;
    long long Modulus;
    long long HostInter;
    long long HostRandom;
    long long SlaveInterKey;
    long long SlaveRandom;
    long long KeyHost;
    long long KeySlave;
}SSP_KEYS;

/* command status enumeration */
typedef enum{
	PORT_CLOSED,
	PORT_OPEN,
	PORT_ERROR,
	SSP_REPLY_OK,
	SSP_PACKET_ERROR,
	SSP_CMD_TIMEOUT,
}PORT_STATUS;

typedef struct {
	SSP_FULL_KEY Key;
	unsigned long Timeout;
	unsigned char SSPAddress;
	unsigned char RetryLevel;
	unsigned char EncryptionStatus;
    SSP_PORT_WP port;
}SSP_COMMAND_SETUP;

typedef struct {
    unsigned char event;
    unsigned long data;
    unsigned char notesCount;
    char currency[3];
} SSP_POLL_EVENT;

typedef struct {
    SSP_POLL_EVENT events[20];
    unsigned char event_count;
} SSP_POLL_DATA;

typedef struct{
    unsigned char UnitType;
    char FirmwareVersion[5];
    char CountryCode[4];
    unsigned long ValueMultiplier;
    unsigned char ProtocolVersion;
}SSP_UNIT_DATA;

typedef struct{
    unsigned char NumberOfChannels;
    unsigned char ChannelData[16];
}SSP_CHANNEL_DATA;

typedef struct {
    unsigned char UnitType;
    char FirmwareVersion[5];
    char CountryCode[4];
    unsigned long ValueMultiplier;
    SSP_CHANNEL_DATA ChannelValues;
    SSP_CHANNEL_DATA ChannelSecurity;
    unsigned long RealValueMultiplier;
    unsigned char ProtocolVersion;
}SSP_SETUP_REQUEST_DATA;

/*
Name: SSPSendCommand
Inputs:
    SSP_PORT The port handle (returned from OpenSSPPort) of the port to use
    SSP_COMMAND The command structure to be used.
Return:
    1 on success
    0 on failure
Notes:
    In the ssp_command structure:
    EncryptionStatus,SSPAddress,Timeout,RetryLevel,CommandData,CommandDataLength (and Key if using encrpytion) must be set before calling this function
    ResponseStatus,ResponseData,ResponseDataLength will be altered by this function call.
*/
int  SSPSendCommand( const SSP_PORT_WP&,SSP_COMMAND* cmd);

/*
Name: OpenSSPPort
Inputs:
    char * port: The name of the port to use (eg /dev/ttyUSB0 for usb serial, /dev/ttyS0 for com port 1)
Return:
    -1 on error
Notes:
*/
SSP_PORT OpenSSPPort(const char * port);

/*
Name: CloseSSPPort
Inputs:
    SSP_PORT port: The port you wish to close
Return:
    void
Notes:
*/
void CloseSSPPort( SSP_PORT& port );

/*

Name: DownloadFileToTarget
Inputs:
    char *file: The full path of the file to download
    char * port: The name of the port to use (eg /dev/ttyUSB0 for usb serial, /dev/ttyS0 for com port 1)
    unsigned char sspAddress: The ssp address to download to
    key: The encryption key to use. 0 to disable encryption
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
    The download is done in a seperate thread - see GetDownloadStatus() for information about its progress.
    Only one download operation may be in progress at once.
*/
uint32_t DownloadFileToTarget(const char * file, const char * port, const unsigned char sspAddress, const unsigned long long key);

/*
Name:   DownloadDataToTarget
Inputs:
    char * data: The array of data you wish to download
    long data_length: length of data to download
    char * port: The name of the port to use (eg /dev/ttyUSB0 for usb serial, /dev/ttyS0 for com port 1)
    unsigned char sspAddress: The ssp address to download to
    key: The encryption key to use. 0 to disable encryption
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
    The download is done in a seperate thread - see GetDownloadStatus() for information about its progress
    Only one download operation may be in progress at once.
*/
uint32_t _downloadDataToTarget(const unsigned char* data, const unsigned long dlength, const char * cPort, const unsigned char sspAddress,const unsigned long long key);

/*
Name:   GetDownloadStatus
Inputs:
    None
Return:
    If the value is less than 0x100000 it is the block number being downloaded.
    After the download process has finished (either successfully or not), the value will be 0x100000 (DOWNLOAD_COMPLETE) for a complete download
    or one of the following for a failure:
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

*/
uint32_t GetDownloadStatus(void);
uint32_t GetFwBlocksCount(void);

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
int NegotiateSSPEncryption(const SSP_PORT_WP& port, const char ssp_address, SSP_FULL_KEY * key);


//SSP functions
/*
The following functions all have an argument of type SSP_COMMAND_SETUP. This contains the information needed to send the command.
The user needs to set:
    EncryptionStatus to NO_ENCRYPTION
    SSPAddress to the sspaddress
    port to the SSP_PORT handle
    RetryLevel to the number of retrys
    Timeout to the required timeout (in milliseconds)
*/
/*
Name: ssp_setup_encryption
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    unsigned long long fixedkey: The fixed key to be used for SSP Encryption. The default key is 0x0123456701234567
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
    This will set the EncryptionStatus and Key in the SSP_COMMAND_SETUP so any further commands sent with this setup are encrypted.
*/
SSP_RESPONSE_ENUM ssp_setup_encryption(SSP_COMMAND_SETUP * setup,const unsigned long long fixedkey);

/*
Name: ssp_reset
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success. Unit will then reset
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_reset(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_host_protocol
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    unsigned char host_protocol : The version of protocol the host is trying to use
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_host_protocol(SSP_COMMAND_SETUP setup,const unsigned char host_protocol);

/*
Name:   ssp_poll
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    SSP_POLL_DATA * poll_response: A pointer to a poll response structure
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_poll(SSP_COMMAND_SETUP setup,SSP_POLL_DATA * poll_response);

/*
Name:   ssp_get_serial
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    SSP_POLL_DATA * poll_response: A pointer a long value to store the serial in
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_get_serial(SSP_COMMAND_SETUP setup,unsigned long * serial );

/*
Name:   ssp_sync
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_sync(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_disable
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returnedNotes:
*/
SSP_RESPONSE_ENUM ssp_disable(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_enable
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_enable(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_set_inhibits
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    unsigned char lowchannels: Bitmask setting inhibits for the low channels (1-8). A value of 1 in the bit means that channel is enabled
    unsigned char highchannels: Bitmask setting inhibits for the low channels (9-16). A value of 1 in the bit means that channel is enabled
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_set_inhibits(SSP_COMMAND_SETUP setup,const unsigned char lowchannels, const unsigned char highchannels);

/*
Name:   ssp_display_on
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_display_on(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_display_off
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_display_off(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_hold_note
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
    Will only be successful when the unit has a note in escrow
*/
SSP_RESPONSE_ENUM ssp_hold_note(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_unit_data
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    SSP_UNIT_DATA * sud: Pointer to an SSP_UNIT_DATA structure for the data to be stored in
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_unit_data(SSP_COMMAND_SETUP setup, SSP_UNIT_DATA * sud);

/*
Name: ssp_enable_higher_protocol_events
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_enable_higher_protocol_events(SSP_COMMAND_SETUP setup);

/*
Name:   ssp_channel_value_data
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    SSP_CHANNEL_DATA * scd: Pointer to an SSP_CHANNEL_DATA structure for the data to be stored in
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_channel_value_data(SSP_COMMAND_SETUP setup, SSP_CHANNEL_DATA * scd);

/*
Name:   ssp_channel_security_data
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    SSP_CHANNEL_DATA * scd: Pointer to an SSP_CHANNEL_DATA structure for the data to be stored in
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_channel_security_data(SSP_COMMAND_SETUP setup, SSP_CHANNEL_DATA * scd);

/*
Name:
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    unsigned char * last_reject_reason: The reason for the last reject (See SSP Spec for more information)
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_last_reject(SSP_COMMAND_SETUP setup, unsigned char * last_reject_reason);

/*
Name:
Inputs:
    SSP_COMMAND_SETUP * setup: The ssp setup structure used to setup the command
    SSP_SETUP_REQUEST_DATA * setup_request_data: Pointer to an SSP_CHANNEL_DATA structure for the data to be stored in
Return:
    SSP_RESPONSE_OK on success
    On failure any other valid SSP_RESPONSE_ENUM value may be returned
Notes:
*/
SSP_RESPONSE_ENUM ssp_setup_request(SSP_COMMAND_SETUP setup, SSP_SETUP_REQUEST_DATA * setup_request_data);

SSP_RESPONSE_ENUM ssp_reject_note(SSP_COMMAND_SETUP setup);
SSP_RESPONSE_ENUM _ssp_return_values(SSP_PORT_WP port, SSP_COMMAND* sspC);

SSP_RESPONSE_ENUM ssp_set_routing(SSP_COMMAND_SETUP setup, const unsigned long value, const char* currency, const unsigned char route);
SSP_RESPONSE_ENUM ssp_get_routing(SSP_COMMAND_SETUP setup, const unsigned long value, const char* currency, unsigned char* route);

SSP_RESPONSE_ENUM ssp_payout_amount(SSP_COMMAND_SETUP setup, const unsigned long amount, const char* currency);
SSP_RESPONSE_ENUM ssp_payout_by_denomination(SSP_COMMAND_SETUP setup, const std::vector<SSspChannel>& Channels );
SSP_RESPONSE_ENUM ssp_float_payout(SSP_COMMAND_SETUP setup, const unsigned long amount, const char* currency, const unsigned long minimum_payout);
SSP_RESPONSE_ENUM ssp_enable_payout_device(SSP_COMMAND_SETUP setup);
SSP_RESPONSE_ENUM ssp_disable_payout_device(SSP_COMMAND_SETUP setup);

SSP_RESPONSE_ENUM ssp_minimum_payout(SSP_COMMAND_SETUP setup, const char* currency, unsigned long * value);
SSP_RESPONSE_ENUM ssp_payout_by_denomination(SSP_COMMAND_SETUP setup, const unsigned long amount, const unsigned long value, const char* currency);

SSP_RESPONSE_ENUM ssp_get_all_levels( SSP_COMMAND_SETUP setup, std::vector< SSspChannel >& Channels );
SSP_RESPONSE_ENUM ssp_channel_value_data( SSP_COMMAND_SETUP setup, std::vector<SSspChannel>& Channels );

SSP_RESPONSE_ENUM ssp_smart_empty( SSP_COMMAND_SETUP setup );
SSP_RESPONSE_ENUM ssp_get_cashbox_payout_operation_data( SSP_COMMAND_SETUP setup, std::vector<SSspChannel>& Channels );
