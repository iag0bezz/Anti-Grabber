using System.Diagnostics;
using Microsoft.Win32;

namespace AntiGrabber.Shared;

public sealed class UnifiedAppLocator
{
    public IReadOnlyList<AppInstallInfo> DetectAll()
    {
        var results = new Dictionary<string, AppInstallInfo>();

        foreach (var app in SensitiveAppCatalog.Apps)
        {
            var found = DetectByRunningProcess(app)
                ?? DetectByRegistry(app)
                ?? DetectByShortcut(app)
                ?? DetectByAppDataDefaultPath(app)
                ?? DetectByDiskScan(app);

            if (found is not null) results[app.AppId] = found;
        }

        return results.Values.ToList();
    }

    private AppInstallInfo? DetectByRunningProcess(SensitiveAppDefinition app)
    {
        foreach (var processName in app.ProcessNames)
        {
            var name = Path.GetFileNameWithoutExtension(processName);
            Process[] procs;
            try { procs = Process.GetProcessesByName(name); }
            catch { continue; }

            if (procs.Length == 0) continue;

            try
            {
                var exePath = procs[0].MainModule?.FileName;
                if (!string.IsNullOrEmpty(exePath))
                {
                    var installDir = Path.GetDirectoryName(exePath)!;
                    return BuildInfo(app, installDir, DetectionMethod.RunningProcess);
                }
            }
            catch
            {
            }
            finally
            {
                foreach (var p in procs) p.Dispose();
            }
        }
        return null;
    }

    private AppInstallInfo? DetectByRegistry(SensitiveAppDefinition app)
    {
        string[] uninstallRoots =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var root in uninstallRoots)
        {
            using var key = Registry.LocalMachine.OpenSubKey(root);
            if (key is null) continue;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(subKeyName);
                var displayName = subKey?.GetValue("DisplayName") as string;
                if (displayName is null) continue;

                if (!app.RegistryUninstallNameHints.Any(hint =>
                        displayName.Contains(hint, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var installLocation = subKey?.GetValue("InstallLocation") as string;
                if (!string.IsNullOrEmpty(installLocation) && Directory.Exists(installLocation))
                    return BuildInfo(app, installLocation, DetectionMethod.Registry);
            }
        }
        return null;
    }

    private AppInstallInfo? DetectByShortcut(SensitiveAppDefinition app)
    {
        string[] shortcutDirs =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        };

        foreach (var dir in shortcutDirs)
        {
            if (!Directory.Exists(dir)) continue;

            List<string> lnkFiles;
            try
            {
                var enumOptions = new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.System | FileAttributes.ReparsePoint,
                };
                lnkFiles = Directory.EnumerateFiles(dir, "*.lnk", enumOptions).ToList();
            }
            catch
            {
                continue;
            }

            foreach (var lnk in lnkFiles)
            {
                if (!app.RegistryUninstallNameHints.Any(hint =>
                        Path.GetFileNameWithoutExtension(lnk).Contains(hint, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var target = ShellLinkResolver.ResolveTarget(lnk);
                if (!string.IsNullOrEmpty(target) && File.Exists(target))
                    return BuildInfo(app, Path.GetDirectoryName(target)!, DetectionMethod.Shortcut);
            }
        }
        return null;
    }

    private AppInstallInfo? DetectByAppDataDefaultPath(SensitiveAppDefinition app)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var relative in app.RelativeAppDataPaths)
        {
            foreach (var basePath in new[] { localAppData, appData })
            {
                var candidate = Path.Combine(basePath, relative);
                if (Directory.Exists(candidate))
                    return BuildInfo(app, candidate, DetectionMethod.AppDataDefaultPath);
            }
        }
        return null;
    }

    private AppInstallInfo? DetectByDiskScan(SensitiveAppDefinition app)
    {
        var roots = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName);

        foreach (var root in roots)
        {
            foreach (var processName in app.ProcessNames)
            {
                var found = ScanForExecutable(root, processName, maxDepth: 3);
                if (found is not null)
                    return BuildInfo(app, Path.GetDirectoryName(found)!, DetectionMethod.DiskScan);
            }
        }
        return null;
    }

    private static string? ScanForExecutable(string root, string exeName, int maxDepth)
    {
        var queue = new Queue<(string Dir, int Depth)>();
        queue.Enqueue((root, 0));

        while (queue.Count > 0)
        {
            var (dir, depth) = queue.Dequeue();
            if (depth > maxDepth) continue;

            string[] subDirs;
            try { subDirs = Directory.GetDirectories(dir); }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                var candidate = Path.Combine(sub, exeName);
                if (File.Exists(candidate)) return candidate;
                queue.Enqueue((sub, depth + 1));
            }
        }
        return null;
    }

    private static AppInstallInfo BuildInfo(SensitiveAppDefinition app, string installPath, DetectionMethod method)
    {
        var sensitiveDirs = app.SensitiveSubPaths
            .Select(sub => Path.Combine(installPath, sub))
            .ToList();

        return new AppInstallInfo(
            app.AppId,
            app.DisplayName,
            installPath,
            method,
            sensitiveDirs,
            app.ProcessNames,
            app.AllowedDomains);
    }
}
