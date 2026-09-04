using System.Runtime.InteropServices;

namespace AntiGrabber.Tray;

internal static class Program
{
    // Trava de instância única via Mutex nomeado — equivalente ao
    // app.requestSingleInstanceLock() do Electron.
    private const string MutexName = "AntiGrabber.Tray.SingleInstance";
    private const string AppUserModelId = "com.antigrabber.tray";

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);

    [STAThread]
    private static void Main()
    {
        using var mutex = new Mutex(initiallyOwned: true, MutexName, out var createdNew);
        if (!createdNew) return;

        // Necessário pra toast (Microsoft.Toolkit.Uwp.Notifications) e pro tray icon
        // agruparem sob a identidade certa em vez de "genérico"/nome do processo.
        SetCurrentProcessExplicitAppUserModelID(AppUserModelId);

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayForm());
    }
}
