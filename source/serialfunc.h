#include "itl_types.h"

uint32_t WriteData( const unsigned char* data, uint32_t length, const SSP_PORT_WP& port, bool bClearRxAccumulator );

int ReadSingleByte( const SSP_PORT_WP& port, unsigned char* buffer, uint32_t nTimeoutMs, bool bClearAccumulator );

void SetBaud( const SSP_PORT_WP& port, const unsigned long baud );

void _itl_ssp_set_comm_logger();
