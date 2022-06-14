#include "ThreadedSerialPort.h"
#include <cstdio>
#include <boost/bind.hpp>
#include <utility>
#include "strings.hpp"

CThreadedSerialPort::CThreadedSerialPort(std::string  strPortName, uint32_t baud, boost::asio::serial_port_base::parity::type parity, uint32_t nCharacterSize,
                                         boost::asio::serial_port_base::stop_bits::type stopBits )
    : m_bStopThread{ false }
    , m_port{ m_io_service }
    , m_timer{ m_io_service }
	, m_strPortName{std::move( strPortName )}
    , m_nBaud{ baud }
    , m_nCharacterSize{ nCharacterSize }
    , m_Parity{ parity }
    , m_StopBits{ stopBits }
    , m_FlowControl{ boost::asio::serial_port_base::flow_control::none }
{	
}

CThreadedSerialPort::~CThreadedSerialPort()
{
    if( m_fnLog ) {
        m_fnLog( false, 0, L"~CSerialPort2() >" );
    }

    StopThread();

    if( m_fnLog ) {
        m_fnLog( false, 0, L"~CSerialPort2() <" );
    }
}

bool CThreadedSerialPort::Open(bool bPurgeRxBuffer )
{
    // Ensure port servicing is stopped
    StopThread();

    return _open( bPurgeRxBuffer );
}

bool CThreadedSerialPort::ChangeSettings(uint32_t baud, uint32_t nCharacterSize, boost::asio::serial_port_base::parity::type parity )
{
    if( m_port.is_open() ){
        m_port.set_option( boost::asio::serial_port::baud_rate( baud ) );
        m_port.set_option( boost::asio::serial_port_base::parity( parity ) );
        m_port.set_option( boost::asio::serial_port_base::character_size( nCharacterSize ) );

        std::wstringstream msg;
        msg << L"Port '" << utf8_to_wstring( m_strPortName ) << L"' opened" << std::endl;
        msg << L"Baudrate: '" << baud << L"'" << std::endl;
        msg << L"Character size: '" << nCharacterSize << L"'" << std::endl;
        msg << L"Parity: '" << parity << L"'" << std::endl;
        msg << L"Stop bits: '" << m_FlowControl << L"'" << std::endl;
        msg << L"Flow control: '" << m_FlowControl << L"'" << std::endl;
        msg << L"Start reading from port '" << utf8_to_wstring( m_strPortName ) << "'";

        if( m_fnLog ) {
            m_fnLog( false, 150, msg.str() );
        }

        return true;
    }

    if( m_fnLog ) {
        m_fnLog( true, 0, L"Port is not open" );
    }
    return false;
}

bool CThreadedSerialPort::SetBaudrate(uint32_t baud )
{
    if( m_port.is_open() ) {

        m_port.set_option( boost::asio::serial_port::baud_rate( baud ) );

        if( m_fnLog ) {
            std::wstringstream msg;
            msg << L"New baudrate: '" << baud << L"'" << std::endl;
            m_fnLog( false, 0, msg.str() );
        }
        return true;
    }

    if( m_fnLog ) {
        m_fnLog( true, 0, L"Port is not open" );
    }
    return false;
}

void CThreadedSerialPort::StartThread(bool bPurgeRxBuffer )
{
    if( m_thread.joinable() ) {
        StopThread();
    }

    // Ensure the port is open
    if( !m_port.is_open() ) {
        _open( bPurgeRxBuffer );
    }

	m_thread = std::thread{
            &CThreadedSerialPort::_fnReadingThread, this
	};
}

void CThreadedSerialPort::StopThread()
{
    if( m_fnLog ) {
        m_fnLog( false, 0, L"CSerialPort2::StopThread() >" );
    }

    {
        std::lock_guard< boost::mutex > _( m_wait_for_incoming_data_mtx );

        m_timer.cancel();

        m_bStopThread = true;

        _close();

        m_wait_for_incoming_data.notify_all();
    }

    if( m_thread.joinable() ) {

        // Additional action to force exiting of reading thread
        m_io_service.stop();

        m_thread.join();
    }
    m_bStopThread = false;

    if( m_fnLog ) {
        m_fnLog( false, 0, L"CSerialPort2::StopThread() <" );
    }
}

bool CThreadedSerialPort::_open(bool bPurgeRxBuffer )
{
    try {
        m_port.open( m_strPortName );
    }
    catch( ... ) {
        if( m_fnLog ) {
            m_fnLog( true, 0, L"Open port failed" );
        }
        return false;
    }

    if( m_port.is_open() ) {
        m_port.set_option( boost::asio::serial_port::baud_rate( m_nBaud ) );
        m_port.set_option( boost::asio::serial_port_base::parity( m_Parity ) );
        m_port.set_option( boost::asio::serial_port_base::character_size(m_nCharacterSize) );
        m_port.set_option( boost::asio::serial_port_base::stop_bits(m_StopBits) );
        m_port.set_option( boost::asio::serial_port_base::flow_control(m_FlowControl) );

        std::wstringstream msg; { };
        msg << L"Port '" << utf8_to_wstring( m_strPortName )<< L"' opened" << std::endl;
        msg << L"Baudrate: '" << m_nBaud << L"'" << std::endl;
        msg << L"Character size: '" << m_nCharacterSize << L"'" << std::endl;
        msg << L"Parity: '" << m_Parity << L"'" << std::endl;
        msg << L"Stop bits: '" << m_StopBits << L"'" << std::endl;
        msg << L"Flow control: '" << m_FlowControl << L"'" << std::endl;
        msg << L"Start reading from port '" << utf8_to_wstring( m_strPortName ) << "'";

        if( m_fnLog ) {
            m_fnLog( false, 150, msg.str() );
        }

        if( bPurgeRxBuffer ) {

            for( ; ; ) {
                std::pair< bool, std::vector< uint8_t > > r = WaitForIncomingData( 1, 10, false );
                if(!r.first) {
                    break;
                }
            }
        }
    }

    return true;
}

void CThreadedSerialPort::_close()
{
    if( m_fnLog ) {
        m_fnLog( false, 0, L"CSerialPort2::_close() >" );
    }

    if( m_port.is_open() ) {
		m_port.cancel();

        int fd{ -1 };
        if( m_bNV200WierdDeinitializationRequired ) {
            // TODO: will this help?
            fd = static_cast< int >( m_port.native_handle() );
            ::tcflush( fd, TCIOFLUSH );
        }

        m_port.close();

        if( m_bNV200WierdDeinitializationRequired ) {
            // TODO: asking for a close one more time
            ::close( fd );
        }
    }

    if( m_fnLog ) {
        m_fnLog( false, 0, L"CSerialPort2::_close() <" );
    }
}

bool CThreadedSerialPort::Write(const std::vector< uint8_t>& pData, bool bClearAccumulator)
{
    if( bClearAccumulator ) {
        std::lock_guard< std::mutex > _lck( m_accum_mtx );
        m_accumulator.clear();
    }

	if( m_fnLog ) {
        std::wostringstream logStream;
        logStream << L"> [SERIAL] write " << pData.size() << L" bytes: " << std::endl << dump_bin_as_string( pData, 1 ) << std::endl;
        m_fnLog( false, 150, logStream.str() );
	}
	try {
        // @note The write_some operation may not transmit all of the data to the
        // peer. Consider using the @ref write function if you need to ensure that
        // all data is written before the blocking operation completes.
        auto nBytesWritten = m_port.write_some( boost::asio::buffer( pData.data(), pData.size() ) );
        for( ; nBytesWritten < pData.size(); ) {
            nBytesWritten += m_port.write_some( boost::asio::buffer( pData.data() + nBytesWritten, pData.size() - nBytesWritten ) );
        }
	}
    catch( std::exception& ex ) {
		if( m_fnLog ) {
            m_fnLog( true, 0, L"Write port failed: " + utf8_to_wstring( ex.what() ) );
		}
		return false;
	}

	return true;
}

void CThreadedSerialPort::_start_port_async_reading()
{
    m_accumulator.clear();
    m_read_buffer.resize( 1 );
    m_port.async_read_some( boost::asio::buffer( m_read_buffer.data(), 1 ),
                            boost::bind(
                                    &CThreadedSerialPort::handle_read, this,
                                    boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred
                            )
    );
}

void CThreadedSerialPort::_fnReadingThread()
{
    if( m_fnLog ) {
        m_fnLog( false, 0, L"CSerialPort2::_fnReadingThread() >" );
    }

	// If the thread is restarted - the service is extremely important to reset
	m_io_service.reset();

    _start_port_async_reading();

	m_io_service.run();

    if( m_fnLog ) {
        m_fnLog( false, 0, L"CSerialPort2::_fnReadingThread() <" );
    }
}

void CThreadedSerialPort::timer_handler()
{
    if( m_bStopThread ) {
        return;
    }
	if( m_port.is_open() ) {
		m_port.cancel();
		m_port.close();
	}
    if( !_open( false ) ) {
		m_timer.expires_from_now( boost::posix_time::seconds( 1 ) );
		m_timer.async_wait( boost::bind(&CThreadedSerialPort::timer_handler, this ) );
	} else {

        // The thread is already initialized. Go back to reading
        _start_port_async_reading();
	}
}

void CThreadedSerialPort::handle_read(const boost::system::error_code& error, size_t bytes_transferred )
{
	if( error.value() != 0 ) {

        if(    boost::asio::error::eof == error
            || boost::asio::error::bad_descriptor == error.value()
        ) {
			// The port is gone. Reopening required
			if( m_fnLog ) {
                std::wostringstream _msg;
                _msg << __func__ << L"() - port closed. Need to reopen" << std::endl;
                m_fnLog( false, 150, _msg.str() );
			}
            _close();
			// The port is gone - cancel the read operation and try to reconnect in the background
			m_timer.expires_from_now( boost::posix_time::seconds( 1 ) );
			m_timer.async_wait( boost::bind(&CThreadedSerialPort::timer_handler, this ) );
			return;
		}

		if( m_fnLog ) {
            std::wostringstream _msg;
            if( boost::asio::error::operation_aborted == error.value() ){
                 _msg << L"handle_read() - read aborted" << std::endl;
                 m_fnLog( false, 150, _msg.str() );
            } else {
                _msg << L"handle_read() - error code:" << error.value() << std::endl;
                m_fnLog( true, 0, _msg.str() );
            }
		}
	}

	bool bReadFinished{ false };
	if( bytes_transferred > 0 ) {

		if( m_fnLog ) {
            std::wostringstream logStream;
            logStream << L"< [SERIAL] " << bytes_transferred << L" bytes received " << std::endl << dump_bin_as_string( m_read_buffer.data(), std::min( m_read_buffer.size(), bytes_transferred ), 1 ) << std::endl;
            m_fnLog( false, 150, logStream.str() );
		}

		{
			std::unique_lock< std::mutex > _lck( m_accum_mtx );
            m_accumulator.insert( m_accumulator.end(), m_read_buffer.cbegin(), m_read_buffer.cbegin() + static_cast< long >( bytes_transferred ) );

            if( m_wait_for_incoming_data_size > 0 ) {

                if( m_fnLog ) {
                    std::wostringstream logStream;
                    logStream << L"< [SERIAL] " <<  m_wait_for_incoming_data_size << L" bytes expected" << std::endl;
                    m_fnLog( false, 150, logStream.str() );
                }
				
                // Test for WaitForIncomingData() finished
                if( m_accumulator.size() >= m_wait_for_incoming_data_size ) {

					bReadFinished = true;
					
					if( m_fnLog ) {
                        std::wostringstream logStream;
                        logStream << L"Read finished. Received: " << std::endl << dump_bin_as_string( { m_accumulator.cbegin(), m_accumulator.cend() }, 1 ) << std::endl;
                        m_fnLog( false, 150, logStream.str() );
					}

					_lck.unlock();

                    std::lock_guard< boost::mutex > _lock( m_wait_for_incoming_data_mtx );
					m_wait_for_incoming_data.notify_all();
				}
            }
		}
	}

    // Stop reading port
	if( m_bStopThread ) {
		return;
	}

    // Adjusting the size of the handle_read buffer for the next upcoming read operation
    size_t bufSize{ 0 };
    {
        std::lock_guard< std::mutex > _lck( m_accum_mtx );
        if( bReadFinished || m_wait_for_incoming_data_size == 0 ) {

            // In case WaitForIncomingData() is inactive
            bufSize = 1;

        } else {

            // WaitForIncomingData() still active
            if( m_wait_for_incoming_data_size <= m_accumulator.size() ) {

                if( m_fnLog ) {
                    // This code are must be unreached
                    std::wostringstream logStream;
                    logStream << L"Logic error! WaitForIncomingData() is active but read expected size is less or equal to accumulator contents. m_wait_for_incoming_data_size = " << m_wait_for_incoming_data_size << L"; m_accumulator.size() = " << m_accumulator.size() << std::endl;
                    m_fnLog( true, 0, logStream.str() );
                }
                bufSize = 1;
            } else {
                bufSize = m_wait_for_incoming_data_size - m_accumulator.size();
            }

            if( bufSize > 0xffff ) {
                std::wostringstream logStream;
                logStream << L"bufSize = " << bufSize << L" is abnormal" << std::endl;
                if( m_fnLog ) {
                    m_fnLog( true, 0, logStream.str() );
                }
            }
        }
    }

	m_read_buffer.resize( bufSize );
	m_port.async_read_some( boost::asio::buffer( m_read_buffer.data(), bufSize ),
		boost::bind(
                &CThreadedSerialPort::handle_read, this,
                boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred
		)
	);
}

std::pair< bool, std::vector< uint8_t > > CThreadedSerialPort::WaitForIncomingData(size_t nBytesCount, uint32_t nTimeoutMillisec, bool bClearAccumulator )
{
    std::pair< bool, std::vector< uint8_t > > response;

    {
        std::lock_guard< std::mutex > _lck( m_accum_mtx );
        if( bClearAccumulator ) {
            m_accumulator.clear();
        }

        // If already have all the data needed to be accumulated in buffer - prepare data for exit
        if( nBytesCount <= m_accumulator.size() ) {
            response.first = true;
            response.second.insert( response.second.begin(), m_accumulator.cbegin(), m_accumulator.cbegin() + static_cast< long >( nBytesCount ) );
            m_accumulator.erase( m_accumulator.begin(), m_accumulator.begin() + static_cast< long >( nBytesCount ) );

            return response;
        }
    }

    m_wait_for_incoming_data_size = nBytesCount;
    if( m_wait_for_incoming_data_size > 0xFFFF ) {
        if( m_fnLog ){
            std::wostringstream logStream;
            logStream << L"nBytesCount = " << nBytesCount << L" is abnormal" << std::endl;
            m_fnLog( true, 0, logStream.str() );
        }
    }


    boost::unique_lock< boost::mutex > _lock( m_wait_for_incoming_data_mtx );
    if( !m_wait_for_incoming_data.wait_for( _lock, boost::chrono::milliseconds( nTimeoutMillisec ),
										   [&] { 
													std::lock_guard< std::mutex > _lck( m_accum_mtx );
													if( m_accumulator.size() >= nBytesCount ) {
														return true;
													} else {
														return m_bStopThread;
													}
												}
	) ) {

		response.first = false;
		return response;
	}

	if( m_bStopThread ) {
		response.first = false;
		return response;
	}
		 
	response.first = true;
    {
		std::lock_guard< std::mutex > _lck( m_accum_mtx );
        response.second.insert( response.second.begin(), m_accumulator.cbegin(), m_accumulator.cbegin() + static_cast< long >( nBytesCount ) );

        m_accumulator.erase( m_accumulator.begin(), m_accumulator.begin() + static_cast< long >( nBytesCount ) );

        m_wait_for_incoming_data_size = 0;
	}
	return response;

}

void CThreadedSerialPort::PurgeRxBuffer()
{
    std::lock_guard< std::mutex > _lck( m_accum_mtx );
    m_accumulator.clear();
}

bool CThreadedSerialPort::TestOpen()
{
    try {

        if( m_port.is_open() ) {
            return  true;
        }
        m_port.open( m_strPortName );
        bool bResult = m_port.is_open();
        m_port.close();

        return bResult;
    }
    catch( ... ) {
        return false;
    }
}

bool CThreadedSerialPort::Send(const std::vector< uint8_t >& vCommand, uint32_t /* nTimeoutUnused */ )
{
    return Write( vCommand );
}

bool CThreadedSerialPort::Receive(const std::vector< uint8_t >&, std::vector< uint8_t >&, uint32_t, uint32_t  )
{
    throw std::runtime_error{ "not implemented" };
}

bool CThreadedSerialPort::SendAndReceive(const std::vector< uint8_t >& vCommand, std::vector< uint8_t >& vAnswer, uint32_t nBytes, uint32_t receiveTimeout )
{
    if( 0 == receiveTimeout ) {
        receiveTimeout = 1000;
    }
    if( !Write( vCommand, true ) ) {
        return false;
    }

    std::pair< bool, std::vector< uint8_t > > result = WaitForIncomingData( nBytes, receiveTimeout, false );
    if( !result.first ) {
        return false;
    }

    vAnswer = result.second;

    return true;
}
