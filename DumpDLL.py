import sys
import pefile
import os
import json
import tabulate
def collectDLLInfo(DLL_File):
	if not DLL_File:
		print("Invalid DLL file.")
		sys.exit(2)
	DLL_File = os.path.abspath(DLL_File)
	if not os.path.isfile(DLL_File):
		print(f"{DLL_File} not found.")
		sys.exit(1)
	PE = pefile.PE(DLL_File)
	if hasattr(PE, "DIRECTORY_ENTRY_EXPORT"):
		if not PE.DIRECTORY_ENTRY_EXPORT.symbols:
			PE.close()
			print("Export table is empty.")
			sys.exit(4)
		Result = []
		ImageBase = PE.OPTIONAL_HEADER.ImageBase
		for Exp in PE.DIRECTORY_ENTRY_EXPORT.symbols:
			Name = Exp.name.decode(errors="ignore") if Exp.name else None
			Ordinal = Exp.ordinal
			if Exp.forwarder:
				Rva = None
				Va = None
			else:
				Rva = Exp.address
				Va = ImageBase + Exp.address
			Forward = Exp.forwarder.decode(errors="ignore") if Exp.forwarder else None
			Result.append({
				"name": Name or "No name",
				"ordinal": Ordinal,
				"rva": hex(Rva) if Rva is not None else "N/A",
				"va": hex(Va) if Va is not None else "N/A",
				"forward": Forward or "No"
			})
		PE.close()
		return Result
	else:
		PE.close()
		print("This DLL does not have an export table.")
		sys.exit(3)
def printDLLInfo(Datas):
	for Data in Datas:
		print("Name:", Data.get("name", None))
		print("Ordinal:", Data.get("ordinal", "unknown"))
		print("Rva:", Data.get("rva", "unknown"))
		print("Va:", Data.get("va", "unknown"))
		print("Forward:", Data.get("forward"))
		print("")
def printJsonDLLInfo(Data):
	print(json.dumps(Data, indent=2))
def printTableDLLInfo(Data):
	print(tabulate.tabulate(Data, headers="keys", tablefmt="grid"))
def showDLLInfo(DLL_File, Mode="normal"):
	Data = collectDLLInfo(DLL_File)
	if Mode.lower() == "table":
		printTableDLLInfo(Data)
	elif Mode.lower() == "json":
		printJsonDLLInfo(Data)
	else:
		printDLLInfo(Data)
	sys.exit(0)
def getVersion():
	return "1.0"
def showVersion():
	print(f"DumpDLL version {getVersion()}")
def showHelp():
	print(f"DumpDLL version {getVersion()} - Simple PE Export Viewer")
	print("")
	print("Usage:")
	print("dumpdll <dll_file> [options]")
	print("")
	print("Options:")
	print("--json                Output result in JSON format.")
	print("--table               Output result in table format.")
	print("--help                Show this help message.")
	print("--version             Show version information.")
	print("")
	print("Output fields:")
	print("Name                  Export function name (or ordinal fallback)")
	print("Ordinal               Export ordinal number")
	print("Rva                   Relative Virtual Address (if not forwarded)")
	print("Va                    Virtual Address (if not forwarded)")
	print("Forward               Forwarded export target (if any)")
	print("")
	print("Examples:")
	print("dumpdll user32.dll")
	print("dumpdll kernel32.dll --table")
	print("dumpdll ntdll.dll --json")
	print("")
def main():
	if len(sys.argv) < 2:
		print("Missing parameters.")
		showHelp()
		sys.exit(2)
	else:
		Args = sys.argv[1:]
		Mode = "normal"
		if "--json" in Args:
			Mode = "json"
			Args.remove("--json")
		if "--table" in Args:
			Mode = "table"
			Args.remove("--table")
		if not Args:
			print("Missing parameters.")
			showHelp()
			sys.exit(2)
		if Args[0].lower() == "--version":
			showVersion()
			sys.exit(0)
		if Args[0].lower() == "--help":
			showHelp()
			sys.exit(0)
		else:
			showDLLInfo(DLL_File=Args[0], Mode=Mode)
if __name__ == "__main__":
	main()