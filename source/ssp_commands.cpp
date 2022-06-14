#include "ITLSSPProc.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <utility>
#include <unistd.h>


#include "Random.h"
#include "Encryption.h"
#include "SSPComs.h"
#include "serialfunc.h"
#include "strings.hpp"
#include <pthread.h>

SSP_RESPONSE_ENUM _ssp_return_values(SSP_PORT_WP port,SSP_COMMAND * sspC)
{
    //CHECK FOR TIMEOUT
    if (SSPSendCommand(std::move(port),sspC) == 0)
        return SSP_RESPONSE_TIMEOUT;
    if (sspC->ResponseStatus != SSP_REPLY_OK)
        return SSP_RESPONSE_TIMEOUT;
    if ((sspC->ResponseData[0] == SSP_RESPONSE_COMMAND_NOT_PROCESSED) && (sspC->ResponseDataLength > 1))
    {
        switch (sspC->ResponseData[1])
        {
            case 0x3:
                return SSP_RESPONSE_COMMAND_NOT_PROCESSED_BUSY;
        }
    }

    return static_cast< SSP_RESPONSE_ENUM >( sspC->ResponseData[0] );
}

void _ssp_setup_command_structure(SSP_COMMAND_SETUP * setup, SSP_COMMAND * sspC)
{
    sspC->Timeout = setup->Timeout;
    sspC->EncryptionStatus = setup->EncryptionStatus;
    sspC->SSPAddress = setup->SSPAddress;
    sspC->RetryLevel = setup->RetryLevel;
    sspC->Key = setup->Key;
}

SSP_RESPONSE_ENUM ssp_setup_encryption(SSP_COMMAND_SETUP * setup,const unsigned long long fixedkey)
{
    setup->Key.FixedKey = fixedkey;
    if (NegotiateSSPEncryption(setup->port,setup->SSPAddress,&setup->Key) == 0)
        return SSP_RESPONSE_TIMEOUT;
    setup->EncryptionStatus = 1;
    return SSP_RESPONSE_OK;
}

SSP_RESPONSE_ENUM ssp_reset(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_RESET;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_host_protocol(SSP_COMMAND_SETUP setup,const unsigned char host_protocol)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 2;
    sspC.CommandData[0] = SSP_CMD_HOST_PROTOCOL;
    sspC.CommandData[1] = host_protocol;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}


SSP_RESPONSE_ENUM ssp_poll(SSP_COMMAND_SETUP setup,SSP_POLL_DATA * poll_response)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i,j;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_POLL;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        poll_response->event_count = 0;
        for (i = 1; i < sspC.ResponseDataLength; ++i)
        {
            poll_response->events[poll_response->event_count].event = sspC.ResponseData[i];
            switch (sspC.ResponseData[i])
            {
            //all these commands have one data byte
            case SSP_POLL_CREDIT:
            case SSP_POLL_FRAUD_ATTEMPT:
            case SSP_POLL_READ:
            case SSP_POLL_STACKED:
            case SSP_POLL_CLEARED_FROM_FRONT:
            case SSP_POLL_CLEARED_INTO_CASHBOX:
                i++; //move onto the data
                poll_response->events[poll_response->event_count].data = sspC.ResponseData[i];
                break;
            //all these commands have 4 data bytes
            case SSP_POLL_DISPENSED:
            case SSP_POLL_DISPENSING:
            case SSP_POLL_HELD_IN_BEZEL:
            case SSP_POLL_JAMMED:
            case SSP_POLL_HALTED:
            case SSP_POLL_FLOATING:
            case SSP_POLL_FLOATED:
            case SSP_POLL_TIMEOUT:
            case SSP_POLL_INCOMPLETE_PAYOUT:
            case SSP_POLL_INCOMPLETE_FLOAT:
            case SSP_POLL_CASHBOX_PAID:
            case SSP_POLL_COIN_CREDIT:
            case SSP_POLL_COIN_VALUE:
            case SSP_POLL_STORED_IN_PAYOUT:
            case SSP_POLL_SMART_EMPTIED:
            case SSP_POLL_SMART_EMPTYING:
                poll_response->events[poll_response->event_count].data = 0;
                poll_response->events[poll_response->event_count].notesCount = sspC.ResponseData[++i];
                for (j = 0; j < 4; ++j)
                {
                    ++i; //move through the data
                    poll_response->events[poll_response->event_count].data += (((unsigned long)sspC.ResponseData[i]) << (8*i));
                }
                for (j = 0; j < 3; ++j)
                {
                    ++i; //move through the data
                    poll_response->events[poll_response->event_count].currency[j] = (sspC.ResponseData[i]);
                }
                break;
            default: //every other command has no data bytes
                poll_response->events[poll_response->event_count].data = 0;
                break;
            }
            poll_response->event_count++;
        }
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_get_serial(SSP_COMMAND_SETUP setup,unsigned long * serial )
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_SERIAL_NUMBER;
    resp = _ssp_return_values(setup.port, &sspC);
    *serial = 0;
    if (resp == SSP_RESPONSE_OK)
    {
        for (i = 0; i < 4; ++i)
          *serial += (((unsigned long)sspC.ResponseData[i+1]) << (8*(3-i)));
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_sync(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_SYNC;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_disable(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_DISABLE;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}


SSP_RESPONSE_ENUM ssp_enable(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_ENABLE;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_disable_coinmech(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 2;
    sspC.CommandData[0] = SSP_CMD_SET_COIN_GLOBAL_INHIBIT;
    sspC.CommandData[1] = 0x00;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_enable_coinmech(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 2;
    sspC.CommandData[0] = SSP_CMD_SET_COIN_GLOBAL_INHIBIT;
    sspC.CommandData[1] = 0x01;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_set_inhibits(SSP_COMMAND_SETUP setup,const unsigned char lowchannels, const unsigned char highchannels)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 3;
    sspC.CommandData[0] = SSP_CMD_SET_INHIBITS;
    sspC.CommandData[1] = lowchannels;
    sspC.CommandData[2] = highchannels;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_display_off(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_BULB_OFF;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_display_on(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_BULB_ON;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_reject_note(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_REJECT_NOTE;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_hold_note(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_HOLD;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_enable_higher_protocol_events(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_ENABLE_HIGHER_PROTOCOL;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}



SSP_RESPONSE_ENUM ssp_unit_data(SSP_COMMAND_SETUP setup, SSP_UNIT_DATA * sud)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    int i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_UNIT_DATA;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        sud->UnitType = sspC.ResponseData[1];
        for (i = 0; i < 4; ++i)
            sud->FirmwareVersion[i] = sspC.ResponseData[i+2];
        sud->FirmwareVersion[i] = 0; //NULL TERMINATOR

        for (i = 0; i < 3; ++i)
            sud->CountryCode[i] = sspC.ResponseData[i+6];
        sud->CountryCode[i] = 0; //NULL TERMINATOR

        sud->ValueMultiplier = 0;
        for (i = 0; i < 3; ++i)
            sud->ValueMultiplier += ((unsigned long)sspC.ResponseData[i+9] << ((2-i)*8));

        sud->ProtocolVersion = sspC.ResponseData[12];

    }
    return resp;
}


SSP_RESPONSE_ENUM ssp_channel_value_data(SSP_COMMAND_SETUP setup, SSP_CHANNEL_DATA * scd)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    int i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_CHANNEL_VALUES;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        scd->NumberOfChannels = sspC.ResponseData[1];
        for (i = 0; i < scd->NumberOfChannels; ++i)
            scd->ChannelData[i] = sspC.ResponseData[i+2];
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_channel_security_data(SSP_COMMAND_SETUP setup, SSP_CHANNEL_DATA * scd)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    int i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_CHANNEL_SECURITY;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        scd->NumberOfChannels = sspC.ResponseData[1];
        for (i = 0; i < scd->NumberOfChannels; ++i)
            scd->ChannelData[i] = sspC.ResponseData[i+2];
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_last_reject(SSP_COMMAND_SETUP setup, unsigned char * last_reject_reason)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_LAST_REJECT;
    resp = _ssp_return_values(setup.port, &sspC);
    *last_reject_reason = 0;
    if (resp == SSP_RESPONSE_OK)
    {
        *last_reject_reason = sspC.ResponseData[1];
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_setup_request(SSP_COMMAND_SETUP setup, SSP_SETUP_REQUEST_DATA * setup_request_data)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    int i;
    int offset;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_SETUP_REQUEST;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        offset = 1;
        setup_request_data->UnitType = sspC.ResponseData[offset++];
        for (i = 0; i < 4; ++i)
            setup_request_data->FirmwareVersion[i] = sspC.ResponseData[offset++];
        setup_request_data->FirmwareVersion[i] = 0; //NULL TERMINATOR

        for (i = 0; i < 3; ++i)
            setup_request_data->CountryCode[i] = sspC.ResponseData[offset++];
        setup_request_data->CountryCode[i] = 0; //NULL TERMINATOR

        setup_request_data->ValueMultiplier = 0;
        for (i = 0; i < 3; ++i)
            setup_request_data->ValueMultiplier += ((unsigned long)sspC.ResponseData[offset++] << ((2-i)*8));

        setup_request_data->ChannelValues.NumberOfChannels = sspC.ResponseData[offset++];
        setup_request_data->ChannelSecurity.NumberOfChannels = setup_request_data->ChannelValues.NumberOfChannels;

        for(i =0 ; i < setup_request_data->ChannelValues.NumberOfChannels; ++i)
            setup_request_data->ChannelValues.ChannelData[i] = sspC.ResponseData[offset++];

        for(i =0 ; i < setup_request_data->ChannelValues.NumberOfChannels; ++i)
            setup_request_data->ChannelSecurity.ChannelData[i] = sspC.ResponseData[offset++];

        setup_request_data->RealValueMultiplier = 0;
        for (i = 0; i < 3; ++i)
            setup_request_data->RealValueMultiplier += ((unsigned long)sspC.ResponseData[offset++] << ((2-i)*8));

        setup_request_data->ProtocolVersion = sspC.ResponseData[offset++];

    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_payout_amount(SSP_COMMAND_SETUP setup, const unsigned long amount, const char* currency)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 9;
    sspC.CommandData[0] = SSP_CMD_PAYOUT_VALUE;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+1] = ((amount >> (8*i))& 0xFF);

    for (i=0; i<3; i++){
        sspC.CommandData[i+5] = currency[i];
    }
    sspC.CommandData[8] = 0x58;

    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_payout_by_denomination(SSP_COMMAND_SETUP setup, const std::vector<SSspChannel>& Channels )
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i, j;
    auto _size = static_cast< uint8_t>( Channels.size() );
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 3 + ( 9 * _size );
    sspC.CommandData[0] = SSP_CMD_PAYOUT_DENOMINATION;
    sspC.CommandData[1] = _size;

    for( j = 0; j < _size ; ++j ){
    for (i = 0; i < 2; ++i){
        auto a = ((Channels[j].nValue >> (8*i))& 0xFF);
        sspC.CommandData[i+2 +j*9] = a;
    }
    for (i = 0; i < 4; ++i){
        auto a = ((Channels[j].nNominal >> (8*i))& 0xFF);
        sspC.CommandData[i+4 + j*9 ] = a;
    }
    for( i = 0; i < 3; ++i ){
        std::string currency = wstring_to_utf8( Channels[j].strCode );
        sspC.CommandData[i+8 + j*9] = currency[i];
    }
    }
    sspC.CommandData[sspC.CommandDataLength - 1 ] = 0x58;

    resp = _ssp_return_values(setup.port, &sspC);

    return resp;
}

SSP_RESPONSE_ENUM ssp_set_coin_amount(SSP_COMMAND_SETUP setup, const unsigned long value, const unsigned short amount)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 7;
    sspC.CommandData[0] = SSP_CMD_SET_COIN_AMOUNT;
    for (i = 0; i < 2; ++i)
        sspC.CommandData[i+1] = ((amount >> (8*i))& 0xFF);
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+3] = ((value >> (8*i))& 0xFF);
    /*sspC.CommandData[7] = 'E';
    sspC.CommandData[8] = 'U';
    sspC.CommandData[9] = 'R';*/

    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}


SSP_RESPONSE_ENUM ssp_get_coin_amount(SSP_COMMAND_SETUP setup, const unsigned long value, unsigned short * amount)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 5;
    sspC.CommandData[0] = SSP_CMD_GET_COIN_AMOUNT;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+3] = ((value >> (8*i))& 0xFF);
    resp = _ssp_return_values(setup.port, &sspC);
    *amount = 0;
    if (resp == SSP_RESPONSE_OK)
        *amount = (unsigned short)sspC.ResponseData[1] + (((unsigned short)sspC.ResponseData[2]) << 8);
    return resp;
}

SSP_RESPONSE_ENUM ssp_halt_payout(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_HALT_PAYOUT;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_set_routing(SSP_COMMAND_SETUP setup,const unsigned long value, const char* currency, const unsigned char route)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 9;
    sspC.CommandData[0] = SSP_CMD_SET_ROUTING;
    sspC.CommandData[1] = route;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+2] = ((value >> (8*i))& 0xFF);

    for (i=0; i<3; i++){
        sspC.CommandData[i+6] = currency[i];
    }
    
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_get_routing(SSP_COMMAND_SETUP setup,const unsigned long value, const char* currency, unsigned char * route)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 8;
    sspC.CommandData[0] = SSP_CMD_GET_ROUTING;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+1] = ((value >> (8*i))& 0xFF);

    for (i=0; i<3; i++){
        sspC.CommandData[i+5] = currency[i];
    }
    
    resp = _ssp_return_values(setup.port, &sspC);
    *route = 0;
    if (resp == SSP_RESPONSE_OK)
        *route = sspC.ResponseData[1];
    return resp;
}

SSP_RESPONSE_ENUM ssp_float_hopper(SSP_COMMAND_SETUP setup,const unsigned long value,  const unsigned long minimum_payout)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 7;
    sspC.CommandData[0] = SSP_CMD_FLOAT;
    for (i = 0; i < 2; ++i)
        sspC.CommandData[i+1] = ((minimum_payout >> (8*i))& 0xFF);
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+3] = ((value >> (8*i))& 0xFF);
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}


SSP_RESPONSE_ENUM ssp_float_payout(SSP_COMMAND_SETUP setup,const unsigned long amount, const char* currency,  const unsigned long minimum_payout)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 13;
    sspC.CommandData[0] = SSP_CMD_FLOAT;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+1] = ((minimum_payout >> (8*i))& 0xFF);
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+5] = ((amount >> (8*i))& 0xFF);
    for( i = 0; i < 3; ++i ){
        sspC.CommandData[i+9] = currency[i];
    }
    sspC.CommandData[12] = 0x58;

    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}


SSP_RESPONSE_ENUM ssp_minimum_payout(SSP_COMMAND_SETUP setup, const char* currency, unsigned long * value )
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 4;
    sspC.CommandData[0] = SSP_CMD_MINIMUM_PAYOUT;
    for( i = 0; i < 3; ++i ){
        sspC.CommandData[i+1] = currency[i];
    }

    resp = _ssp_return_values(setup.port, &sspC);
    *value = 0;
    if (resp == SSP_RESPONSE_OK)
    {
         for (i = 0; i < 4; ++i)
            *value += (((unsigned long)sspC.ResponseData[1+i]) << (8*i));
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_empty(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_EMPTY;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_enable_payout_device(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_ENABLE_PAYOUT_DEVICE;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_disable_payout_device(SSP_COMMAND_SETUP setup)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_DISABLE_PAYOUT_DEVICE;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}


SSP_RESPONSE_ENUM ssp_set_host_serial(SSP_COMMAND_SETUP setup,const unsigned long serial)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 5;
    sspC.CommandData[0] = SSP_CMD_HOST_SERIAL;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[i+1] = ((serial >> (8*i))& 0xFF);
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_set_coin_inhibit(SSP_COMMAND_SETUP setup,const unsigned long value,const unsigned char state)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 6;
    sspC.CommandData[0] = SSP_CMD_SET_COIN_INHIBIT;
    sspC.CommandData[1] = state;
    for (i = 0; i < 4; ++i)
        sspC.CommandData[1+i] = ((value >> (8*i))& 0xFF);
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_setup_request_hopper(SSP_COMMAND_SETUP setup, SSP_SETUP_REQUEST_DATA * setup_request_data)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    int i;
    int offset;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_SETUP_REQUEST;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        offset = 1;
        setup_request_data->UnitType = sspC.ResponseData[offset++];
        for (i = 0; i < 4; ++i)
            setup_request_data->FirmwareVersion[i] = sspC.ResponseData[offset++];
        setup_request_data->FirmwareVersion[i] = 0; //NULL TERMINATOR

        for (i = 0; i < 3; ++i)
            setup_request_data->CountryCode[i] = sspC.ResponseData[offset++];
        setup_request_data->CountryCode[i] = 0; //NULL TERMINATOR

        setup_request_data->ChannelValues.NumberOfChannels = sspC.ResponseData[offset++];

        for(i =0 ; i < setup_request_data->ChannelValues.NumberOfChannels; ++i)
        {
            setup_request_data->ChannelValues.ChannelData[i] = sspC.ResponseData[offset++];
            setup_request_data->ChannelValues.ChannelData[i] += ((unsigned short)sspC.ResponseData[offset++] << 8);
        }


        setup_request_data->ProtocolVersion = sspC.ResponseData[offset++];

    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_payout_by_denomination(SSP_COMMAND_SETUP setup, const unsigned long amount, const unsigned long value, const char* currency)
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    unsigned char i;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 12;
    sspC.CommandData[0] = SSP_CMD_PAYOUT_DENOMINATION;
    sspC.CommandData[1] = 1;
    for (i = 0; i < 2; ++i){
        auto a = ((amount >> (8*i))& 0xFF);
        sspC.CommandData[i+2] = a;
    }
    for (i = 0; i < 4; ++i){
        auto a = ((value >> (8*i))& 0xFF);
        sspC.CommandData[i+4] = a;
    }
    for( i = 0; i < 3; ++i ){
        sspC.CommandData[i+8] = currency[i];
    }
    sspC.CommandData[11] = 0x58;

    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_channel_value_data( SSP_COMMAND_SETUP setup, std::vector<SSspChannel>& Channels )
{
    SSP_COMMAND sspC;
    sspC.Timeout = setup.Timeout;
    sspC.EncryptionStatus = setup.EncryptionStatus;
    sspC.SSPAddress = setup.SSPAddress;
    sspC.RetryLevel = setup.RetryLevel;
    sspC.Key = setup.Key;

    SSP_RESPONSE_ENUM resp;
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_CHANNEL_VALUES;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        uint8_t nChannels = sspC.ResponseData[1];
        for (uint8_t i = 0; i < nChannels; ++i)
        {
            SSspChannel Channel;
            Channel.nValue = sspC.ResponseData[i + 2];
            Channel.strCode.push_back(static_cast<char>(sspC.ResponseData[3 * i + nChannels + 2]));
            Channel.strCode.push_back(static_cast<char>(sspC.ResponseData[3 * i + nChannels + 3]));
            Channel.strCode.push_back(static_cast<char>(sspC.ResponseData[3 * i + nChannels + 4]));
            Channel.nNominal = sspC.ResponseData[4 * i + 4 * nChannels + 2] +
                    sspC.ResponseData[4 * i + 4 * nChannels + 3] * 256 +
                    sspC.ResponseData[4 * i + 4 * nChannels + 4] * 256 * 256 +
                    sspC.ResponseData[4 * i + 4 * nChannels + 5] * 256 * 256 * 256;
            Channels.push_back(Channel);
        }
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_get_all_levels( SSP_COMMAND_SETUP setup, std::vector< SSspChannel >& Channels )
{
    SSP_COMMAND sspC;
    sspC.Timeout = setup.Timeout;
    sspC.EncryptionStatus = setup.EncryptionStatus;
    sspC.SSPAddress = setup.SSPAddress;
    sspC.RetryLevel = setup.RetryLevel;
    sspC.Key = setup.Key;

    SSP_RESPONSE_ENUM resp;
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_GET_ALL_LEVELS;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        // uint8_t nChannels = sspC.ResponseData[1];
        for( uint8_t i = 1; i <= sspC.ResponseDataLength - 2; ){
            SSspChannel Channel;
            for( int j = 0; j < 2; ++j ){
                ++i; //move through the data
                Channel.nValue += ( ( sspC.ResponseData[i] ) << (8*j));
            }

            //Channel.nValue = sspC.ResponseData[++i];
            for ( uint32_t j = 0; j < 4; ++j)
            {
                ++i; //move through the data
                Channel.nNominal += ( static_cast< uint32_t >( sspC.ResponseData[i] ) << ( 8 * j ) );
            }
            for (int j = 0; j < 3; ++j)
            {
                ++i; //move through the data
                Channel.strCode.push_back(sspC.ResponseData[i]);
            }
            Channels.push_back( Channel );
        }
    }
    return resp;
}

SSP_RESPONSE_ENUM ssp_smart_empty( SSP_COMMAND_SETUP setup )
{
    SSP_COMMAND sspC;
    SSP_RESPONSE_ENUM resp;
    _ssp_setup_command_structure(&setup,&sspC);
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_SMART_EMPTY;
    resp = _ssp_return_values(setup.port, &sspC);
    return resp;
}

SSP_RESPONSE_ENUM ssp_get_cashbox_payout_operation_data( SSP_COMMAND_SETUP setup, std::vector<SSspChannel>& Channels )
{
    SSP_COMMAND sspC;
    sspC.Timeout = setup.Timeout;
    sspC.EncryptionStatus = setup.EncryptionStatus;
    sspC.SSPAddress = setup.SSPAddress;
    sspC.RetryLevel = setup.RetryLevel;
    sspC.Key = setup.Key;

    SSP_RESPONSE_ENUM resp;
    sspC.CommandDataLength = 1;
    sspC.CommandData[0] = SSP_CMD_CASHBOX_PAYOUT_OPERATION_DATA;
    resp = _ssp_return_values(setup.port, &sspC);
    if (resp == SSP_RESPONSE_OK)
    {
        // uint8_t nChannels = sspC.ResponseData[1];
        for( uint8_t i = 1; i <= sspC.ResponseDataLength - 2; ){
            SSspChannel Channel;
            for( int j = 0; j < 2; ++j ){
                ++i; //move through the data
                Channel.nValue += ( ( sspC.ResponseData[i] ) << (8*j));
            }

            //Channel.nValue = sspC.ResponseData[++i];
            for ( int j = 0; j < 4; ++j)
            {
                ++i; //move through the data
                Channel.nNominal += ((sspC.ResponseData[i]) << (8*j));
            }
            for (int j = 0; j < 3; ++j)
            {
                ++i; //move through the data
                Channel.strCode.push_back(sspC.ResponseData[i]);
            }
            Channels.push_back( Channel );
        }
    }
    return resp;
}

