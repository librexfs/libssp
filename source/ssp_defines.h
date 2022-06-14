#ifndef __SSP_DEFINES_H
#define __SSP_DEFINES_H


#define SSP_STX 0x7F


//Standard BNV SSP Commands
#define SSP_CMD_RESET 0x1
#define SSP_CMD_SET_INHIBITS 0x2
#define SSP_CMD_BULB_ON 0x3
#define SSP_CMD_BULB_OFF 0x4
#define SSP_CMD_SETUP_REQUEST 0x5
#define SSP_CMD_HOST_PROTOCOL 0x6
#define SSP_CMD_POLL 0x7
#define SSP_CMD_REJECT_NOTE 0x8
#define SSP_CMD_DISABLE 0x9
#define SSP_CMD_ENABLE 0xA
#define SSP_CMD_PROGRAM 0xB //See SSP_PROGRAM_* defintions for second byte
#define SSP_CMD_SERIAL_NUMBER 0xC
#define SSP_CMD_UNIT_DATA 0xD
#define SSP_CMD_CHANNEL_VALUES 0xE
#define SSP_CMD_CHANNEL_SECURITY 0xF
#define SSP_CMD_CHANNEL_RETEACH 0x10
#define SSP_CMD_SYNC 0x11
#define SSP_CMD_DISPENSE 0x12
#define SSP_CMD_PROGRAM_STATUS 0x16
#define SSP_CMD_LAST_REJECT 0x17
#define SSP_CMD_HOLD 0x18
#define SSP_CMD_MANUFACTURER 0x30
#define SSP_CMD_EXPANSION 0x30
#define SSP_CMD_ENABLE_HIGHER_PROTOCOL 0x19

//PAYOUT and HOPPER COMMANDS
#define SSP_CMD_GET_ALL_LEVELS 0x22
#define SSP_CMD_PAYOUT_VALUE 0x33
#define SSP_CMD_PAYOUT_BY_DENOMINATION 0x46
#define SSP_CMD_SET_COIN_AMOUNT 0x34
#define SSP_CMD_GET_COIN_AMOUNT 0x35
#define SSP_CMD_HALT_PAYOUT     0x38
#define SSP_CMD_SET_ROUTING 0x3B
#define SSP_CMD_GET_ROUTING 0x3C
#define SSP_CMD_FLOAT 0x3D
#define SSP_CMD_MINIMUM_PAYOUT 0x3E
#define SSP_CMD_SET_COIN_INHIBIT 0x40
#define SSP_CMD_EMPTY   0x3F
#define SSP_CMD_HOST_SERIAL 0x14
#define SSP_CMD_ENABLE_PAYOUT_DEVICE 0x5C
#define SSP_CMD_DISABLE_PAYOUT_DEVICE 0x5B
#define SSP_CMD_SET_COIN_GLOBAL_INHIBIT 0x49
#define SSP_CMD_PAYOUT_DENOMINATION	0x46
#define SSP_CMD_SMART_EMPTY 0x52
#define SSP_CMD_CASHBOX_PAYOUT_OPERATION_DATA 0x53

//generic SSP Responses
typedef enum
{
SSP_RESPONSE_OK = 0xF0,
SSP_RESPONSE_UNKNOWN_COMMAND = 0xF2,
SSP_RESPONSE_INCORRECT_PARAMETERS =  0xF3,
SSP_RESPONSE_INVALID_PARAMETER = 0xF4,
SSP_RESPONSE_COMMAND_NOT_PROCESSED = 0xF5,
SSP_RESPONSE_SOFTWARE_ERROR = 0xF6,
SSP_RESPONSE_CHECKSUM_ERROR = 0xF7,
SSP_RESPONSE_FAILURE = 0xF8,
SSP_RESPONSE_HEADER_FAILURE = 0xF9,
SSP_RESPONSE_KEY_NOT_SET = 0xFA,
SSP_RESPONSE_TIMEOUT = 0xFF,
SSP_RESPONSE_COMMAND_NOT_PROCESSED_BUSY = 0xF503,
} SSP_RESPONSE_ENUM;


//Poll Responses
enum eStatus: uint8_t {
    SSP_POLL_INITIAL_STATE = 0x00,
    SSP_POLL_CONNECTION_PROBLEMS = 0x01,
    SSP_POLL_RESET = 0xF1,
    SSP_POLL_READ = 0xEF, //next byte is channel (0 for unknown)
    SSP_POLL_CREDIT = 0xEE,  //next byte is channel
    SSP_POLL_REJECTING = 0xED,
    SSP_POLL_REJECTED = 0xEC,
    SSP_POLL_STACKING = 0xCC,
    SSP_POLL_STACKED = 0xEB,
    SSP_POLL_SAFE_JAM = 0xEA,
    SSP_POLL_UNSAFE_JAM = 0xE9,
    SSP_POLL_DISABLED = 0xE8,
    SSP_POLL_FRAUD_ATTEMPT = 0xE6, //next byte is channel
    SSP_POLL_STACKER_FULL = 0xE7,
    SSP_POLL_CLEARED_FROM_FRONT = 0xE1,
    SSP_POLL_CLEARED_INTO_CASHBOX = 0xE2,
    SSP_POLL_BARCODE_VALIDATE = 0xE5,
    SSP_POLL_BARCODE_ACK = 0xD1,
    SSP_POLL_CASH_BOX_REMOVED = 0xE3,
    SSP_POLL_CASH_BOX_REPLACED = 0xE4,
    SSP_POLL_DISPENSING = 0xDA,
    SSP_POLL_DISPENSED = 0xD2,
    SSP_POLL_JAMMED = 0xD5,
    SSP_POLL_HALTED = 0xD6,
    SSP_POLL_FLOATING = 0xD7,
    SSP_POLL_FLOATED = 0xD8,
    SSP_POLL_TIMEOUT = 0xD9,
    SSP_POLL_INCOMPLETE_PAYOUT = 0xDC,
    SSP_POLL_INCOMPLETE_FLOAT = 0xDD,
    SSP_POLL_CASHBOX_PAID = 0xDE,
    SSP_POLL_COIN_CREDIT = 0xDF,
    SSP_POLL_EMPTYING = 0xC2,
    SSP_POLL_EMPTY = 0xC3,
    SSP_POLL_COINS_LOW = 0xD3,
    SSP_POLL_COINS_EMPTY = 0xD4,
    SSP_POLL_COIN_VALUE = 0xBF,
    SSP_POLL_COIN_MECH_DISABLED = 0xBD,
    SSP_POLL_COIN_MECH_ENABLED = 0xBE,
    SSP_POLL_NOTE_PATH_OPEN = 0xE0,
    SSP_POLL_CHANNEL_DISABLE = 0xB5,
    SSP_POLL_INITIALISING = 0xB6,
    SSP_POLL_SMART_EMPTYING = 0xB3,
    SSP_POLL_SMART_EMPTIED = 0xB4,
    SSP_POLL_STORED_IN_PAYOUT = 0xDB,
    SSP_POLL_JAM_RECOVERY = 0xB0,
    SSP_POLL_ERROR_DURING_PAYOUT = 0xB1,
    SSP_POLL_TRANSFERED_TO_STACKER = 0xC9,
    SSP_POLL_HELD_IN_BEZEL = 0xCE,
    SSP_POLL_INTO_STORE_AT_RESET = 0xCB,
    SSP_POLL_INTO_STACKER_AT_RESET = 0xCA
};


//Programming Type
#define SSP_PROGRAM_FIRMWARE 0x0
#define SSP_PROGRAM_DATASET 0x1
#define SSP_PROGRAM_RAM 0x3

//channel definitions
#define SSP_CHANNEL_ONE 0x1
#define SSP_CHANNEL_TWO 0x2
#define SSP_CHANNEL_THREE 0x3
#define SSP_CHANNEL_FOUR 0x4
#define SSP_CHANNEL_FIVE 0x5
#define SSP_CHANNEL_SIX 0x6
#define SSP_CHANNEL_SEVEN 0x7
#define SSP_CHANNEL_EIGHT 0x8
#define SSP_CHANNEL_NINE 0x9
#define SSP_CHANNEL_TEN 0xA
#define SSP_CHANNEL_ELEVEN 0xB
#define SSP_CHANNEL_TWELVE 0xC
#define SSP_CHANNEL_THIRTEEN 0xD
#define SSP_CHANNEL_FOURTEEN 0xE
#define SSP_CHANNEL_FIFTEEN 0xF
#define SSP_CHANNEL_SIXTEEN 0x10

//encryped
#define SSP_CMD_SET_GENERATOR 0x4A
#define SSP_CMD_SET_MODULUS 0x4B
#define SSP_CMD_REQ_KEY_EXCHANGE 0x4C

//download
#define DOWNLOAD_COMPLETE				0x100000
#define OPEN_FILE_ERROR					0x100001
#define READ_FILE_ERROR					0x100002
#define NOT_ITL_FILE					0x100003
#define PORT_OPEN_FAIL					0x100004
#define SYNC_CONNECTION_FAIL			0x100005
#define	SECURITY_PROTECTED_FILE			0x100006

#define DATA_TRANSFER_FAIL				0x100010
#define PROG_COMMAND_FAIL				0x100011
#define HEADER_FAIL						0x100012
#define PROG_STATUS_FAIL				0x100013
#define PROG_RESET_FAIL					0x100014
#define DOWNLOAD_NOT_ALLOWED			0x100015
#define HI_TRANSFER_SPEED_FAIL			0x100016

#define DOWNLOAD_STARTED                0x200000

#endif
