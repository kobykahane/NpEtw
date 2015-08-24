#NpEtw

NpEtw is a sniffer for named pipe I/O operations on Windows. It can be used to monitor create, read, write and other operations on named pipes in the system.

NpEtw is implemented as a file system minifilter driver that attaches to the named pipe file system, Npfs. Since the Filter Manager introduced support for attaching to the named pipe and mailslot file systems in Windows 8, that OS or higher are required. The minifilter acts as an Event Tracing for Windows (ETW) provider. Therefore NpEtw by itself has no UI of any kind. It is used in conjunction with an ETW consumer such as Microsoft Message Analyzer.

##Building

The minifilter driver itself requires Visual Studio 2015 and Windows Driver Kit 10 to build. The project that builds the MSI package requires version 3.10 or higher of the Wix (Windows Installer XML) toolset.

##Example usage

* Enable test signing in the target system by running `bcdedit /set testsigning on` from an elevated command prompt.
* Install the NpEtw MSI package.
* Run Microsoft Message Analyzer. Go to the File menu -> New session -> Live trace. In the *Add Provider* textbox, type NpEtw and click it. NpEtw will appear in the ETW Providers list. Click Start to start the session.
