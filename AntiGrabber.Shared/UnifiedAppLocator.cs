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
        foreach (var relative in app.RelativeAppDataPaths)
        {
            foreach (var basePath in UserDataBases(UserProfileDirectories()))
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

    // SensitiveSubPaths are always defined relative to the app's user-data root
    // (RelativeAppDataPaths), which can differ from wherever the exe/install dir
    // was found (e.g. Discord's exe lives in a versioned %LocalAppData%\Discord\app-x.y.z
    // folder, but its "Local Storage\leveldb" is under %AppData%\Discord). Resolve
    // that root directly instead of trusting whichever detection method happened to
    // win. Local and Roaming AppData can both have a same-named folder (Discord's
    // install lives under Local, its data under Roaming) so a candidate only counts
    // if it actually contains one of the sensitive subpaths — matching by folder
    // name alone picks the wrong root.
    //
    // The service runs as LocalSystem, whose own AppData is the systemprofile one —
    // so the roots come from every real user profile on the machine, not from the
    // current process. Each profile with data contributes its own paths.
    public static IReadOnlyList<string> ResolveSensitiveDirectories(SensitiveAppDefinition app, IEnumerable<string> profileDirs)
    {
        var result = new List<string>();
        if (app.RelativeAppDataPaths.Length == 0 || app.SensitiveSubPaths.Length == 0) return result;

        foreach (var profile in profileDirs)
        {
            foreach (var relative in app.RelativeAppDataPaths)
            {
                var root = UserDataBases(new[] { profile })
                    .Select(b => Path.Combine(b, relative))
                    .FirstOrDefault(candidate => app.SensitiveSubPaths.Any(sub => Exists(Path.Combine(candidate, sub))));
                if (root is null) continue;
                result.AddRange(app.SensitiveSubPaths.Select(sub => Path.Combine(root, sub)));
                break;
            }
        }
        return result;
    }

    // Subpath com curinga (ex: "ssfn*") existe se algum arquivo bate no diretório pai.
    private static bool Exists(string path)
    {
        if (Directory.Exists(path) || File.Exists(path)) return true;
        var name = Path.GetFileName(path);
        if (!name.Contains('*')) return false;
        var dir = Path.GetDirectoryName(path);
        try { return dir is not null && Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir, name).Any(); }
        catch { return false; }
    }

    // ponytail: AppData no caminho padrão do perfil — redirecionamento de pasta (GPO) fica de fora.
    private static IEnumerable<string> UserDataBases(IEnumerable<string> profileDirs)
    {
        foreach (var profile in profileDirs)
        {
            yield return Path.Combine(profile, "AppData", "Roaming");
            yield return Path.Combine(profile, "AppData", "Local");
            yield return profile; // ex: %USERPROFILE%\.lunarclient
        }
    }

    /// Perfis de usuário reais (contas locais/Microsoft/domínio, SID S-1-5-21-*) do ProfileList.
    public static IReadOnlyList<string> UserProfileDirectories()
    {
        var result = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            foreach (var sid in key?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) continue;
                using var sub = key!.OpenSubKey(sid);
                if (sub?.GetValue("ProfileImagePath") is string path)
                {
                    path = Environment.ExpandEnvironmentVariables(path);
                    if (Directory.Exists(path)) result.Add(path);
                }
            }
        }
        catch
        {
        }

        var current = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (result.Count == 0 && Directory.Exists(current)) result.Add(current);
        return result;
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
        var sensitiveDirs = ResolveSensitiveDirectories(app, UserProfileDirectories()).ToList();
        if (sensitiveDirs.Count == 0)
            sensitiveDirs = app.SensitiveSubPaths.Select(sub => Path.Combine(installPath, sub)).ToList();

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
