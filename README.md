# DumpDLL
Name: DumpDLL  
Version: 1.0  
Platform: Windows  
Simple PE Export Viewer
## Usage:
dumpdll <dll_file> [options]  
### Options:
- --json                Output result in JSON format.  
- --table               Output result in table format.  
- --help                Show this help message.  
- --version             Show version information.  
## Output fields:
- Name                  Export function name (or ordinal fallback).  
- Ordinal               Export ordinal number.  
- Rva                   Relative Virtual Address (if not forwarded).  
- Va                    Virtual Address (if not forwarded).  
- Forward               Forwarded export target (if any).  
## Examples:
- dumpdll user32.dll  
- dumpdll kernel32.dll --table  
dumpdll ntdll.dll --json  
## Download:
Download and read release note at:
https://github.com/NguyenVuHoangLong2012/DumpDLL/releases
