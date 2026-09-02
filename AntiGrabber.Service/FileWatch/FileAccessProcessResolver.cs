using System.Runtime.InteropServices;
using System.Text;

namespace AntiGrabber.Service.FileWatch;

internal static class FileAccessProcessResolver
{
    public static int? TryResolveAccessingPid(string path)
    {
        if (!File.Exists(path)) return null;

        uint session = 0;
        var sessionKey = new StringBuilder(CCH_RM_SESSION_KEY + 1);

        if (RmStartSession(out session, 0, sessionKey) != 0) return null;

        try
        {
            var resources = new[] { path };
            if (RmRegisterResources(session, (uint)resources.Length, resources, 0, null!, 0, null!) != 0)
                return null;

            uint pnProcInfoNeeded = 0;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = RmRebootReasonNone;

            var result = RmGetList(session, out pnProcInfoNeeded, ref pnProcInfo, null!, ref lpdwRebootReasons);
            if (result == ErrorMoreData && pnProcInfoNeeded > 0)
            {
                var processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                pnProcInfo = pnProcInfoNeeded;
                result = RmGetList(session, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                if (result == 0 && pnProcInfo > 0)
                {
                    return (int)processInfo[0].Process.dwProcessId;
                }
            }
        }
        catch
        {
        }
        finally
        {
            RmEndSession(session);
        }

        return null;
    }

    private const int CCH_RM_SESSION_KEY = 32;
    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;
    private const uint ErrorMoreData = 234;
    private const uint RmRebootReasonNone = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public uint dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        uint pSessionHandle,
        uint nFiles,
        string[] rgsFilenames,
        uint nApplications,
        RM_UNIQUE_PROCESS[] rgApplications,
        uint nServices,
        string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
        ref uint lpdwRebootReasons);
}
