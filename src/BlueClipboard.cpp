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

// No clipboard integration on Linux yet: it needs a display-server protocol (X11 selections or Wayland
// wl_data_device), which blue does not talk to. Report failure so callers fall back gracefully.
BlueClipboard::OperationResult BlueClipboard::GetData( std::string& ) const
{
	return CLIPBOARD_FAILURE;
}

BlueClipboard::OperationResult BlueClipboard::GetData( std::wstring& ) const
{
	return CLIPBOARD_FAILURE;
}

BlueClipboard::OperationResult BlueClipboard::SetData( const std::string& )
{
	return CLIPBOARD_FAILURE;
}

BlueClipboard::OperationResult BlueClipboard::SetData( const std::wstring& )
{
	return CLIPBOARD_FAILURE;
}

#endif // __linux__
