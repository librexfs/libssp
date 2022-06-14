#define BSD_COMP
#include <cstdio>   /* Standard input/output definitions */
#include <cstring>  /* String function definitions */
#include <unistd.h>  /* UNIX standard function definitions */
#include <fcntl.h>   /* File control definitions */
#include <cerrno>   /* Error number definitions */
#include <termios.h> /* POSIX terminal control definitions */
#include <sys/ioctl.h>
#include "itl_types.h"
#include "serialfunc.h"

namespace {
    std::mutex g_log_mtx;
}

void _itl_ssp_set_comm_logger( )
{
    std::lock_guard< std::mutex > _{ g_log_mtx };
}

// port is the device name ( eg /dev/ttyACM0 )
// returns -1 on error
/*
    Name: OpenSSPPort
    Inputs:
        char * port: The name of the port to use (eg /dev/ttyUSB0 for usb serial, /dev/ttyS0 for com port 1)
    Return:
        -1 on error
    Notes:
*/

SSP_PORT OpenSSPPort(const char * port)
{
    SSP_PORT pPort;

    pPort.reset( new CThreadedSerialPort(
        port, 9600,
        boost::asio::serial_port_base::parity::none,
        8, boost::asio::serial_port_base::stop_bits::two
    ) );

    if( !pPort->Open() ) {
        pPort.reset();
        return {};
    }
    pPort->_setNV200WierdDeinitializationRequired();

    pPort->StartThread();

    return pPort;
}

/*
Name: CloseSSPPort
Inputs:
    SSP_PORT port: The port you wish to close
Return:
    void
Notes:
*/
void CloseSSPPort( SSP_PORT& pPort )
{
    if( pPort ) {
        pPort->StopThread();
        pPort.reset();
    }
}

uint32_t WriteData( const unsigned char * data, uint32_t length, const SSP_PORT_WP& port, bool bClearRxAccumulator )
{
    if( auto pPort = port.lock() ) {

        std::vector< uint8_t > vData;
        std::copy( data, data + length, std::back_inserter( vData ) );
        if( !pPort->Write( vData, bClearRxAccumulator ) ) {
            return 0;
        }
        return length;
    }
    return 0;
}

int ReadSingleByte( const SSP_PORT_WP& port, unsigned char* buffer, uint32_t nTimeoutMs, bool bClearAccumulator )
{
    if( auto pPort = port.lock() ) {
        auto result = pPort->WaitForIncomingData( 1, nTimeoutMs, bClearAccumulator );
        if( !result.first ) {
            return 0;
        }
        *buffer = result.second[ 0 ];
        return 1;
    }
    return 0;
}

void SetBaud( const SSP_PORT_WP& port, const unsigned long baud )
{
    if( auto pPort = port.lock() ) {
        pPort->SetBaudrate( static_cast< uint32_t >( baud ) );
    }
}
