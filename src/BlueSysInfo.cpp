// Copyright © 2015 CCP ehf.

#include "StdAfx.h"
#include "BlueSysInfo.h"
#include "pdm.h"
#include "pdm/protobuf.h"
#include "BlueMemStream.h"
#ifdef _WIN32
#include "win32.h"
#include <ShlObj.h>
#include <intrin.h>
#endif
#include <sstream>

static CcpLogChannel_t s_ch = CCP_LOG_DEFINE_CHANNEL( "BlueSysInfo" );

BlueSysInfoTaskTimesPtr BlueSysInfo::GetProcessTimes() const
{
	BlueSysInfoTaskTimesPtr times;
	times.CreateInstance();

	int64_t kernelTime, userTime;
	if( !CcpGetProcessTimes( kernelTime, userTime ) )
	{
		PyErr_SetString( PyExc_OSError, "Failed to get process times" );
		return nullptr;
	}
	times->m_systemTime = double( kernelTime ) / 10000000.0;
	times->m_userTime = double( userTime ) / 10000000.0;
	return times;
}

BlueSysInfoTaskTimesPtr BlueSysInfo::GetThreadTimes() const
{
	BlueSysInfoTaskTimesPtr times;
	times.CreateInstance();

	int64_t kernelTime, userTime;
	if( !CcpGetThreadTimes( kernelTime, userTime ) )
	{
		PyErr_SetString( PyExc_OSError, "Failed to get thread times" );
		return nullptr;
	}
	times->m_systemTime = double( kernelTime ) / 10000000.0;
	times->m_userTime = double( userTime ) / 10000000.0;
	return times;
}

BlueSysInfoMemoryPtr BlueSysInfo::GetMemory() const
{
	BlueSysInfoMemoryPtr memory;
	memory.CreateInstance();
	return memory;
}

bool BlueSysInfo::IsRosetta() const
{
    return PDM::IsRosetta();
}

bool BlueSysInfo::IsWine() const
{
	return PDM::IsWine();
}

std::wstring BlueSysInfo::GetWineVersion() const
{
	return UTF8ToWide( PDM::GetWineVersion() );
}

std::wstring BlueSysInfo::GetWineHostOs() const
{
	return UTF8ToWide( PDM::GetWineHostOs() );
}

std::vector<BlueSysInfoNetworkAdapterPtr> BlueSysInfo::GetNetworkAdapters() const
{
	std::vector<BlueSysInfoNetworkAdapterPtr> adapters;

	for( auto& adapter : PDM::GetNetworkAdapterInfo() )
	{
		BlueSysInfoNetworkAdapterPtr ptr;
		ptr.CreateInstance();
		ptr->m_name = UTF8ToWide( adapter.name );
		const auto& mac = adapter.macAddress;
		auto macAddressByteString = std::string( mac.begin(), mac.end() );
		ptr->m_macAddress = PyBytes_FromStringAndSize( macAddressByteString.c_str(), macAddressByteString.size() );
		ptr->m_macAddressString = adapter.macAddressString;
		ptr->m_uuid = adapter.uuidString;

		adapters.push_back( ptr );
	}

	return adapters;
}

std::wstring BlueSysInfo::GetPDMData() const
{
	return UTF8ToWide( PDM::PDMDataToFormattedString( PDM::RetrievePDMData( "EVE", "" ) ) );
}

#ifdef _WIN32

std::wstring BlueSysInfo::GetUserDocumentsDirectory() const
{
    wchar_t path[MAX_PATH];
    if( SUCCEEDED( SHGetFolderPathW( NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, path ) ) )
    {
        return path;
    }
    return L"";
}

std::wstring BlueSysInfo::GetSharedApplicationDataDirectory() const
{
    wchar_t path[MAX_PATH];
    if( SUCCEEDED( SHGetFolderPathW( NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, path ) ) )
    {
        return path;
    }
    return L"";
}

std::wstring BlueSysInfo::GetUserApplicationDataDirectory() const
{
    wchar_t path[MAX_PATH];
    if( SUCCEEDED( SHGetFolderPathW( NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, path ) ) )
    {
        return path;
    }
    return L"";
}

std::wstring BlueSysInfo::GetSharedFontsDirectory() const
{
    wchar_t path[MAX_PATH];
	if( SUCCEEDED( SHGetFolderPathW( NULL, CSIDL_FONTS, NULL, SHGFP_TYPE_CURRENT, path ) ) )
    {
        return path;
    }
    return L"";
}

std::wstring BlueSysInfo::GetSystemFontsDirectory() const
{
	// Windows only has one fonts directory
	return GetSharedFontsDirectory();
}

uint32_t BlueSysInfo::GetProcessBitCount() const
{
	return CcpGetProcessBitCount();
}

uint32_t BlueSysInfo::GetSystemBitCount() const
{
#ifdef _WIN64
	return 64;
#else
	BOOL isWow = FALSE;
	IsWow64Process( GetCurrentProcess(), &isWow );
	return isWow ? 64 : 32;
#endif
}

uint64_t BlueSysInfo::GetProcessStartTime() const
{
	FILETIME creationTime, exitTime, kernelTime, userTime;
	if( ::GetProcessTimes( GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime ) )
	{
		ULARGE_INTEGER lg;
		lg.HighPart = creationTime.dwHighDateTime;
		lg.LowPart = creationTime.dwLowDateTime;
		return lg.QuadPart;
	}
	else
	{
		return 0;
	}
}

std::string BlueSysInfo::GetMachineUuid() const
{
	REGSAM access = KEY_READ;
#ifndef _WIN64
	if( GetSystemBitCount() != 32 )
	{
		access |= KEY_WOW64_64KEY;
	}
#endif
	HKEY key;
	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, access, &key ) != ERROR_SUCCESS )
	{
		return "";
	}
	ON_BLOCK_EXIT( [&] { RegCloseKey( key ); } );

	DWORD type;
	char guid[256];
	DWORD size = DWORD( sizeof( guid ) );
	if( RegQueryValueEx( key, "MachineGuid", nullptr, &type, reinterpret_cast<LPBYTE>( guid ), &size ) != ERROR_SUCCESS )
	{
		return "";
	}
	if( type != REG_SZ )
	{
		return "";
	}
	return guid;
}

std::wstring BlueSysInfo::GetMachineName() const
{
	wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
	buffer[0] = 0;
	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameW( buffer, &size );
	return buffer;
}

std::wstring BlueSysInfo::GetDomainName() const
{
	DWORD size = 0;
	GetComputerNameExW( ComputerNamePhysicalDnsDomain, nullptr, &size );

	std::unique_ptr<wchar_t[]> buffer( new wchar_t[size] );
	if( !GetComputerNameExW( ComputerNamePhysicalDnsDomain, buffer.get(), &size ) )
	{
		return {};
	}

	wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
	name[0] = 0;
	size = MAX_COMPUTERNAME_LENGTH + 1;
	DnsHostnameToComputerNameW( buffer.get(), name, &size );
	return name;
}



BlueSysInfoCpu::BlueSysInfoCpu() :
	m_extensions( PDM::GetCPUInfo().extensions )
{
	auto pdmCpu = PDM::GetCPUInfo();
	m_mHz = pdmCpu.frequency;
	SYSTEM_INFO info;
	GetNativeSystemInfo( &info );

	m_family = info.wProcessorLevel;
	m_revision = info.wProcessorRevision;
	m_logicalCpuCount = info.dwNumberOfProcessors;

	int cpuInfo[4] = { 0 };
	__cpuid( cpuInfo, 0x80000000 );
	int idMax = cpuInfo[0];
	if ( idMax >= 0x80000001 )
	{
		__cpuidex( cpuInfo, 0x80000001, 0 );
		m_bitCount = cpuInfo[3] & ( 1 << 29 ) ? 64 : 32;
	}
	else
	{
		m_bitCount = 32;
	}

	char brand[0x40] = { 0 };

	if ( idMax >= 0x80000004 )
	{
		__cpuidex( reinterpret_cast<int*>( brand ), 0x80000002, 0 );
		__cpuidex( reinterpret_cast<int*>( brand + 16 ), 0x80000003, 0 );
		__cpuidex( reinterpret_cast<int*>( brand + 32 ), 0x80000004, 0 );
	}
	m_brand = brand;

	char vendor[0x20] = { 0 };
	__cpuidex( cpuInfo, 0, 0 );
	*reinterpret_cast<int*>(vendor) = cpuInfo[1];
    *reinterpret_cast<int*>(vendor + 4) = cpuInfo[3];
    *reinterpret_cast<int*>(vendor + 8) = cpuInfo[2];

	int model = 0;
	int stepping = 0;

	__cpuid( cpuInfo, 0 );
	idMax = cpuInfo[0];
	if( idMax > 0 )
	{
		__cpuidex( cpuInfo, 1, 0 );
		model = ( ( cpuInfo[0] >> 4 ) & 0xf ) | ( ( cpuInfo[0] >> 12 ) & 0xf0 );
		stepping = cpuInfo[0] & 0xf;
	}


	const char* platform;
	switch( info.wProcessorArchitecture )
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		m_architecture = "AMD64";
		platform = strstr( vendor, "Intel" ) ? "Intel64" : "AMD64";
		break;
	case PROCESSOR_ARCHITECTURE_ARM:
		m_architecture = "ARM";
		platform = "ARM";
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		m_architecture = "IA64";
		platform = "IA64";
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		m_architecture = "x86";
		platform = "x86";
		break;
	case PROCESSOR_ARCHITECTURE_ARM64:
		m_architecture = "ARM64";
		platform = "ARM64";
		break;
	default:
		platform = "Unknown";
	}
	char identifier[128];
	sprintf_s( identifier, "%s Family %i Model %i Stepping %i, %s", platform, m_family, model, stepping, vendor );
	m_identifier = identifier;
}


BlueSysInfoOs::BlueSysInfoOs()
{
	m_platform = WINDOWS;

	OSVERSIONINFOEX info = { 0 };
	info.dwOSVersionInfoSize = sizeof( info );
	GetWindowsVersion( info );

	m_majorVersion = info.dwMajorVersion;
	m_minorVersion = info.dwMinorVersion;
	m_buildNumber = info.dwBuildNumber;
	m_patch = info.szCSDVersion;
	if( info.wProductType > 1 )
	{
		m_suite = SERVER;
	}
	else if( ( info.wSuiteMask & 0x00000200 ) != 0 )
	{
		m_suite = DESKTOP;
	}
	else
	{
		m_suite = WORKSTATION;
	}
}

BlueSysInfoMemory::BlueSysInfoMemory()
{
	CcpProcessMemoryInfo info;
	if ( CcpGetProcessMemoryInfo( info ) ) {
		m_workingSet = uint64_t( info.workingSetSize );
		m_pageFile = uint64_t( info.pageFileUsage );
	}

	MEMORYSTATUSEX status;
	status.dwLength = DWORD( sizeof( status ) );
	GlobalMemoryStatusEx( &status );
	m_totalPhysical = uint64_t( status.ullTotalPhys );
	m_availablePhysical = uint64_t( status.ullAvailPhys );
}

#endif



BlueSysInfoNetworkAdapter::BlueSysInfoNetworkAdapter() {}

const BlueSysInfoCpu& BlueSysInfo::GetCpuInfo() const
{
    return m_cpu;
}

const BlueSysInfoOs& BlueSysInfo::GetOsInfo() const
{
    return m_os;
}

BlueStdResult GetPDMByteData( IBlueStream** pdm_stream )
{
	BlueStdResult result;

	std::stringstream buffer;

	auto can_serialize = pdm_proto::GetEVEPublicData( &buffer );
	if( can_serialize )
	{
		std::string pdm_data = buffer.str();
		MemStreamPtr contents;
		contents.CreateInstance();
		contents->Write( pdm_data.data(), pdm_data.size() );
		contents->Seek( 0, ICcpStream::SO_BEGIN );
		*pdm_stream = contents.Detach();
		result = BlueStdResult( BLUE_STD_RESULT_OK );
	}
	else
	{
		result = BlueStdResult( BLUE_STD_RESULT_IO_ERROR, "Failed to serialize pdm data" );
		CCP_LOGERR_CH( s_ch, result.GetMessage() );
	}

	return result;
}


#ifdef __linux__

#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <cstdlib>

namespace
{
	// Process start time in the FILETIME convention the Windows implementation returns:
	// 100 ns ticks since 1601-01-01.
	int64_t FileTimeNow()
	{
		timeval now;
		gettimeofday( &now, nullptr );
		return ( int64_t( now.tv_sec ) + 11644473600LL ) * 10000000LL + int64_t( now.tv_usec ) * 10;
	}
	const int64_t s_startTime = FileTimeNow();

	std::wstring HomeDirectory()
	{
		const char* home = getenv( "HOME" );
		return home ? std::wstring( CA2W( home ) ) : std::wstring();
	}

	// XDG base directory: the environment variable when set, otherwise $HOME + fallback.
	std::wstring XdgDirectory( const char* variable, const wchar_t* fallback )
	{
		const char* value = getenv( variable );
		if( value && *value )
		{
			return std::wstring( CA2W( value ) );
		}
		std::wstring home = HomeDirectory();
		return home.empty() ? std::wstring() : home + fallback;
	}

	// A directory from $XDG_CONFIG_HOME/user-dirs.dirs, where xdg-user-dirs keeps entries such as
	// XDG_DOCUMENTS_DIR="$HOME/Documents". Falls back to $HOME, as xdg-user-dir does.
	std::wstring XdgUserDirectory( const char* key )
	{
		std::wstring home = HomeDirectory();
		std::wstring config = XdgDirectory( "XDG_CONFIG_HOME", L"/.config" );
		std::ifstream dirs( std::string( CW2A( ( config + L"/user-dirs.dirs" ).c_str() ) ) );
		std::string line;
		std::string prefix = std::string( key ) + "=";
		while( std::getline( dirs, line ) )
		{
			if( line.compare( 0, prefix.size(), prefix ) != 0 )
			{
				continue;
			}
			std::string value = line.substr( prefix.size() );
			if( value.size() >= 2 && value.front() == '"' && value.back() == '"' )
			{
				value = value.substr( 1, value.size() - 2 );
			}
			std::wstring result;
			if( value.compare( 0, 5, "$HOME" ) == 0 )
			{
				result = home + std::wstring( CA2W( value.substr( 5 ).c_str() ) );
			}
			else if( !value.empty() && value.front() == '/' )
			{
				result = std::wstring( CA2W( value.c_str() ) );
			}
			struct stat info;
			if( !result.empty() && stat( std::string( CW2A( result.c_str() ) ).c_str(), &info ) == 0 && S_ISDIR( info.st_mode ) )
			{
				return result;
			}
			break;
		}
		return home;
	}

	// First "key\t: value" line of /proc/cpuinfo for the given key.
	std::string CpuInfoField( const char* key )
	{
		std::ifstream cpuinfo( "/proc/cpuinfo" );
		std::string line;
		size_t keyLength = strlen( key );
		while( std::getline( cpuinfo, line ) )
		{
			if( line.compare( 0, keyLength, key ) == 0 )
			{
				auto colon = line.find( ':' );
				if( colon != std::string::npos )
				{
					auto start = line.find_first_not_of( " \t", colon + 1 );
					return start == std::string::npos ? std::string() : line.substr( start );
				}
			}
		}
		return std::string();
	}

	// Value in kB of a /proc/meminfo entry such as "MemTotal:".
	uint64_t MemInfoKb( const char* key )
	{
		std::ifstream meminfo( "/proc/meminfo" );
		std::string line;
		size_t keyLength = strlen( key );
		while( std::getline( meminfo, line ) )
		{
			if( line.compare( 0, keyLength, key ) == 0 )
			{
				return strtoull( line.c_str() + keyLength, nullptr, 10 );
			}
		}
		return 0;
	}
}

std::wstring BlueSysInfo::GetUserDocumentsDirectory() const
{
	return XdgUserDirectory( "XDG_DOCUMENTS_DIR" );
}

std::wstring BlueSysInfo::GetSharedApplicationDataDirectory() const
{
	return L"/usr/share";
}

std::wstring BlueSysInfo::GetUserApplicationDataDirectory() const
{
	// The XDG base directory spec asks applications to create $XDG_DATA_HOME (mode 0700) when it is missing;
	// callers treat this like Windows' AppData folder, which always exists.
	std::wstring path = XdgDirectory( "XDG_DATA_HOME", L"/.local/share" );
	if( !path.empty() )
	{
		std::string narrow( CW2A( path.c_str() ) );
		for( size_t slash = narrow.find( '/', 1 ); ; slash = narrow.find( '/', slash + 1 ) )
		{
			mkdir( narrow.substr( 0, slash ).c_str(), 0700 );
			if( slash == std::string::npos )
			{
				break;
			}
		}
	}
	return path;
}

std::wstring BlueSysInfo::GetSharedFontsDirectory() const
{
	return L"/usr/share/fonts";
}

std::wstring BlueSysInfo::GetSystemFontsDirectory() const
{
	return L"/usr/share/fonts";
}

uint32_t BlueSysInfo::GetProcessBitCount() const
{
	return uint32_t( sizeof( void* ) * 8 );
}

uint32_t BlueSysInfo::GetSystemBitCount() const
{
	utsname name;
	if( uname( &name ) == 0 )
	{
		std::string machine( name.machine );
		if( machine == "x86_64" || machine == "aarch64" || machine.find( "64" ) != std::string::npos )
		{
			return 64;
		}
		return 32;
	}
	return GetProcessBitCount();
}

uint64_t BlueSysInfo::GetProcessStartTime() const
{
	return s_startTime;
}

std::string BlueSysInfo::GetMachineUuid() const
{
	for( const char* path : { "/etc/machine-id", "/var/lib/dbus/machine-id" } )
	{
		std::ifstream file( path );
		std::string id;
		if( file && std::getline( file, id ) && !id.empty() )
		{
			return id;
		}
	}
	return "";
}

std::wstring BlueSysInfo::GetMachineName() const
{
	char buffer[256];
	buffer[0] = 0;
	gethostname( buffer, sizeof( buffer ) );
	buffer[sizeof( buffer ) - 1] = 0;
	if( auto dot = strchr( buffer, '.' ) )
	{
		*dot = 0;
	}
	std::string str( buffer );
	return std::wstring( std::begin( str ), std::end( str ) );
}

std::wstring BlueSysInfo::GetDomainName() const
{
	char buffer[256];
	buffer[0] = 0;
	gethostname( buffer, sizeof( buffer ) );
	buffer[sizeof( buffer ) - 1] = 0;
	char* start = buffer;
	if( auto dot = strchr( buffer, '.' ) )
	{
		start = dot + 1;
		dot = strchr( start, '.' );
		if( dot )
		{
			*dot = 0;
		}
	}
	else
	{
		start = buffer + strlen( buffer );
	}
	std::string str( start );
	return std::wstring( std::begin( str ), std::end( str ) );
}

BlueSysInfoCpu::BlueSysInfoCpu() :
	m_extensions( PDM::GetCPUInfo().extensions )
{
	auto pdmCpu = PDM::GetCPUInfo();
	m_mHz = pdmCpu.frequency;
	m_brand = CpuInfoField( "model name" );
	int family = atoi( CpuInfoField( "cpu family" ).c_str() );
	int model = atoi( CpuInfoField( "model" ).c_str() );
	int stepping = atoi( CpuInfoField( "stepping" ).c_str() );
	m_family = family;
	m_revision = ( model << 8 ) | stepping;
	long logical = sysconf( _SC_NPROCESSORS_ONLN );
	m_logicalCpuCount = logical > 0 ? uint32_t( logical ) : 1;
	std::string vendor = CpuInfoField( "vendor_id" );

	const char* platform;
#if __i386__ || __x86_64__
	m_bitCount = 64;
	m_architecture = "AMD64";
	platform = vendor.find( "Intel" ) != std::string::npos ? "Intel64" : "AMD64";
#elif __aarch64__
	m_bitCount = 64;
	m_architecture = "ARM64";
	platform = "ARM64";
#else
	m_bitCount = uint32_t( sizeof( void* ) * 8 );
	m_architecture = "Unknown";
	platform = "Unknown";
#endif

	char identifier[512];
	sprintf_s( identifier, "%s Family %i Model %i Stepping %i, %s", platform, family, model, stepping, vendor.c_str() );
	m_identifier = identifier;
}

BlueSysInfoOs::BlueSysInfoOs()
{
	m_platform = LINUX;
	m_majorVersion = 0;
	m_minorVersion = 0;
	m_buildNumber = 0;
	m_suite = DESKTOP;

	utsname name;
	if( uname( &name ) == 0 )
	{
		// Kernel release such as "6.11.5-300.fc41.x86_64": major.minor.patch, then the distribution suffix.
		m_patch = name.release;
		sscanf( name.release, "%d.%d.%d", &m_majorVersion, &m_minorVersion, &m_buildNumber );
	}
}

BlueSysInfoMemory::BlueSysInfoMemory()
{
	CcpProcessMemoryInfo memInfo;
	if( CcpGetProcessMemoryInfo( memInfo ) )
	{
		m_workingSet = uint64_t( memInfo.workingSetSize );
		m_pageFile = uint64_t( memInfo.pageFileUsage );
	}
	else
	{
		m_workingSet = 0;
		m_pageFile = 0;
	}
	m_totalPhysical = MemInfoKb( "MemTotal:" ) * 1024;
	m_availablePhysical = MemInfoKb( "MemAvailable:" ) * 1024;
	if( !m_totalPhysical )
	{
		struct sysinfo info;
		if( sysinfo( &info ) == 0 )
		{
			m_totalPhysical = uint64_t( info.totalram ) * info.mem_unit;
			m_availablePhysical = uint64_t( info.freeram ) * info.mem_unit;
		}
	}
}

#endif // __linux__
