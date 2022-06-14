#pragma once

#include <utility>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <deque>
#include <iomanip>
#include <boost/asio.hpp>
#include <boost/thread/condition_variable.hpp>

class CThreadedSerialPort {
public:
    CThreadedSerialPort(std::string  strPortName, unsigned int baud, boost::asio::serial_port_base::parity::type parity, uint32_t nCharacterSize,
                        boost::asio::serial_port_base::stop_bits::type stopBits = boost::asio::serial_port_base::stop_bits::one
    );
    virtual ~CThreadedSerialPort();

    void _setNV200WierdDeinitializationRequired() { m_bNV200WierdDeinitializationRequired = true; }

    // Open port, purge input buffer
    // TODO: to be deprecated. Move all the contents of this method to StartThread.
    bool Open( bool bPurgeRxBuffer = true );
    bool IsOpen() { return m_port.is_open(); }
    bool ChangeSettings( uint32_t baud, uint32_t nCharacterSize, boost::asio::serial_port_base::parity::type parity );
    bool SetBaudrate( uint32_t baud );

    // Ensures the port is open then starts the thread
    // TODO: must return bool
    void StartThread( bool bPurgeRxBuffer = true );

    // Stops the thread and also closes the port
    void StopThread();

    void SetLoggerHandler( std::function< void( bool bIsWarning, int lvl, const std::wstring& msg ) > fn ) { m_fnLog = std::move(fn); }

    std::pair< bool, std::vector< uint8_t > > WaitForIncomingData( size_t nBytesCount, uint32_t nTimeoutMillisec, bool bClearAccumulator = false );

    bool Write( const std::vector< uint8_t>& pData, bool bClearAccumulator = false );

private:

    // Close port
    // The access is restricted. To close port use public StopThread()
    bool _open( bool bPurgeRxBuffer = true );
    void _close();

    // Read stream organization
    void _start_port_async_reading();
    void _fnReadingThread();
    void handle_read( const boost::system::error_code& error, size_t bytes_transferred );
    void timer_handler();

private:

    std::thread m_thread;
    bool m_bStopThread{ false };

    std::function< void( bool bIsWarning, int lvl, const std::wstring& msg ) > m_fnLog;

    boost::asio::io_service m_io_service;
    boost::asio::serial_port m_port;
    boost::asio::deadline_timer m_timer;

    std::string m_strPortName;
    uint32_t m_nBaud;
    uint32_t m_nCharacterSize;
    boost::asio::serial_port_base::parity::type m_Parity;
    boost::asio::serial_port_base::stop_bits::type m_StopBits;
    boost::asio::serial_port_base::flow_control::type m_FlowControl;

    // handle_read operation buffer
    std::vector< uint8_t > m_read_buffer;

    // Accumulating data for WaitForIncomingData()
    std::mutex m_accum_mtx;
    std::deque< uint8_t > m_accumulator;
    size_t m_wait_for_incoming_data_size{ 0 };

    boost::mutex m_wait_for_incoming_data_mtx;
    boost::condition_variable m_wait_for_incoming_data;

    bool m_bNV200WierdDeinitializationRequired{ false };

    void PurgeRxBuffer();

    bool TestOpen();

    bool Send(const std::vector<uint8_t> &vCommand, uint32_t);

    bool Receive(const std::vector<uint8_t> &, std::vector<uint8_t> &, uint32_t, uint32_t);

    bool SendAndReceive(const std::vector<uint8_t> &vCommand, std::vector<uint8_t> &vAnswer, uint32_t nBytes,
                        uint32_t receiveTimeout);
};
