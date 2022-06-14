#include <codecvt>
#include <string>

#ifndef ITL_SSP_STRINGS_H
#define ITL_SSP_STRINGS_H

#endif //ITL_SSP_STRINGS_H

using namespace std;

// convert UTF-8 string to wstring
std::wstring utf8_to_wstring (const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8 (const std::wstring& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

std::wstring remove_control_chars( const std::wstring& refStr )
{
    std::wstring strResult;
    std::wstring::const_iterator it = refStr.begin();
    for( ; it != refStr.end(); ++it ) {
        if( iscntrl( *it ) ) {
            strResult += L'.';
        } else {
            strResult += *it;
        }
    }
    return strResult;
}

std::wstring dump_bin_as_string( const uint8_t* pStart, const uint8_t* pEnd, size_t nIndent, size_t nColumns = 16, wchar_t chAsciiBlockDelimiter = L'|')
{
    std::wstring strIndent( nIndent, L'\t' );
    std::wostringstream symbols, tmp_str;
    if( !pStart || !pEnd || pEnd <= pStart ) {
        tmp_str << strIndent << L"[none]";
        return tmp_str.str();
    }
    if( nColumns < 1 ) {
        nColumns = 16; // incorrect data, change
    }

    size_t i = 0;
    auto nSize = static_cast< size_t >( std::distance( pStart, pEnd ) );
    for( ; i < nSize; ++i ) {
        wchar_t sym{ L'?' };
        uint8_t val = *( pStart + i );
        if( val < 0x20 ) {
            sym = L'.';
        } else if( val >= 0x7e ) {
            sym = L'?';
        } else if( val >= 0x20 && val < 0x7e ) {
            sym = static_cast< wchar_t >( val );
        }

        if( 0 == ( i % nColumns ) ) {
            // Flush the line
            if( i > 0 ) {
                tmp_str << L"\t" << chAsciiBlockDelimiter << remove_control_chars( symbols.str() );
                tmp_str << L"\r\n";
            }
            // New line:
            tmp_str << strIndent << std::setw( 4 ) << std::setfill( L'0' ) << std::setbase( 10 ) << i << L":\t";
            symbols.str( L"" );
        }
        tmp_str << std::setw( 2 ) << std::setfill( L'0' ) << std::setbase( 16 ) << static_cast<int>( val ) << L" ";
        symbols << sym;
    }
    // Finish the last line:
    if( 0 != ( i % nColumns ) ) {
        for( size_t k = ( i % nColumns ); k < nColumns; ++k ) {
            tmp_str << L"   ";
        }
    }
    tmp_str << L"\t" << chAsciiBlockDelimiter << remove_control_chars( symbols.str() );
    return tmp_str.str();
}

std::wstring dump_bin_as_string( const std::vector< uint8_t >& _data, size_t nIndent, size_t nColumns = 16, wchar_t chAsciiBlockDelimiter = L'|')
{
    return dump_bin_as_string(_data.data(), _data.data() + _data.size(), nIndent, nColumns, chAsciiBlockDelimiter);
}

std::wstring dump_bin_as_string(const uint8_t* pStart, size_t nSize, size_t nIndent, size_t nColumns = 16, wchar_t chAsciiBlockDelimiter = L'|')
{
    return dump_bin_as_string(pStart, pStart + nSize, nIndent, nColumns, chAsciiBlockDelimiter);
}
