// Copyright © 2021 CCP ehf.

#include "StdAfx.h"
#include "BlueClipboard.h"

#if _WIN32

namespace
{
	template <typename T>
	BlueClipboard::OperationResult GetData( UINT format, std::basic_string<T>& data )
	{
		if( !OpenClipboard( NULL ) )
		{
			return BlueClipboard::CLIPBOARD_FAILURE;
		}
		ON_BLOCK_EXIT( [] { CloseClipboard(); } );

		if( !IsClipboardFormatAvailable( format ) )
		{
			return BlueClipboard::CLIPBOARD_INCOMPATIBLE_FORMAT;
		}

		auto hdata = GetClipboardData( format );
		if( !hdata )
		{
			return BlueClipboard::CLIPBOARD_FAILURE;
		}
		auto size = GlobalSize( hdata );
		if( !size )
		{
			return BlueClipboard::CLIPBOARD_FAILURE;
		}

		auto string = (T*)GlobalLock( hdata );
		if( !string )
		{
			return BlueClipboard::CLIPBOARD_FAILURE;
		}
		data = std::basic_string<T>( string );

		GlobalUnlock( string );

		return BlueClipboard::CLIPBOARD_OK;
	}

	template <typename T>
	BlueClipboard::OperationResult SetData( UINT format, const std::basic_string<T>& data )
	{
		auto len = data.length();
		auto hdata = GlobalAlloc( GMEM_MOVEABLE, ( len + 1 ) * sizeof( T ) );
		if( !hdata )
		{
			return BlueClipboard::CLIPBOARD_FAILURE;
		}
		auto* dest = (T*)GlobalLock( hdata );
		memcpy( dest, data.c_str(), len * sizeof( T ) );
		dest[len] = '\0';
		GlobalUnlock( dest );

		if( !OpenClipboard( NULL ) )
		{
			GlobalDiscard( hdata );
			return BlueClipboard::CLIPBOARD_FAILURE;
		}
		EmptyClipboard();
		SetClipboardData( format, hdata );
		CloseClipboard();
		return BlueClipboard::CLIPBOARD_OK;
	}
}

BlueClipboard::OperationResult BlueClipboard::GetData( std::string& data ) const
{
	return ::GetData( CF_TEXT, data );
}

BlueClipboard::OperationResult BlueClipboard::GetData( std::wstring& data ) const
{
	return ::GetData( CF_UNICODETEXT, data );
}

BlueClipboard::OperationResult BlueClipboard::SetData( const std::string& data )
{
	return ::SetData( CF_TEXT, data );
}

BlueClipboard::OperationResult BlueClipboard::SetData( const std::wstring& data )
{
	return ::SetData( CF_UNICODETEXT, data );
}
#endif

#ifdef __linux__

#include "BluePlatformServices.h"
#include "StringConversions.h"

// The clipboard belongs to the display server; the renderer's window layer provides it (BluePlatformServices).
namespace
{
const BluePlatformServices* s_services = nullptr;
}

void BlueSetPlatformServices( const BluePlatformServices* services )
{
	s_services = services;
}

const BluePlatformServices* BlueGetPlatformServices()
{
	return s_services;
}

BlueClipboard::OperationResult BlueClipboard::GetData( std::string& data ) const
{
	return s_services && s_services->getClipboardText && s_services->getClipboardText( data ) ? CLIPBOARD_OK : CLIPBOARD_FAILURE;
}

BlueClipboard::OperationResult BlueClipboard::GetData( std::wstring& data ) const
{
	std::string utf8;
	auto result = GetData( utf8 );
	if( result == CLIPBOARD_OK )
	{
		data = UTF8ToWide( utf8 );
	}
	return result;
}

BlueClipboard::OperationResult BlueClipboard::SetData( const std::string& data )
{
	return s_services && s_services->setClipboardText && s_services->setClipboardText( data ) ? CLIPBOARD_OK : CLIPBOARD_FAILURE;
}

BlueClipboard::OperationResult BlueClipboard::SetData( const std::wstring& data )
{
	return SetData( WideToUTF8( data ) );
}

#endif // __linux__
