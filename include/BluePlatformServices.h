// Copyright © 2026 CCP ehf.

#pragma once

#include <string>

// Desktop services blue cannot provide by itself on Linux, where they belong to the display server (X11 or Wayland)
// that the renderer's window layer talks to: trinity's Vulkan build registers SDL3-backed implementations when it
// starts its window system. Until something registers, the clipboard reports failure and message boxes go to stderr.
// Strings are UTF-8.
struct BluePlatformServices
{
	bool ( *getClipboardText )( std::string& text );
	bool ( *setClipboardText )( const std::string& text );
	bool ( *showMessageBox )( const char* title, const char* message );
};

// Registers (or, with nullptr, removes) the services; the struct must outlive its registration.
BLUEIMPORT void BlueSetPlatformServices( const BluePlatformServices* services );
BLUEIMPORT const BluePlatformServices* BlueGetPlatformServices();
