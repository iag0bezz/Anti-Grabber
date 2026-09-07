namespace AntiGrabber.Shared;

public sealed record SensitiveAppDefinition(
    string AppId,
    string DisplayName,
    string[] ProcessNames,
    string[] RegistryUninstallNameHints,
    string[] RelativeAppDataPaths,
    string[] SensitiveSubPaths,
    string[] AllowedDomains);

public static class SensitiveAppCatalog
{
    public static readonly IReadOnlyList<SensitiveAppDefinition> Apps = new[]
    {
        new SensitiveAppDefinition(
            AppId: "discord",
            DisplayName: "Discord",
            ProcessNames: new[] { "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe" },
            RegistryUninstallNameHints: new[] { "Discord" },
            RelativeAppDataPaths: new[] { "Discord", "discordcanary", "discordptb" },
            SensitiveSubPaths: new[] { "Local Storage\\leveldb" },
            AllowedDomains: new[] { "discord.com", "discordapp.com", "discordapp.net", "discord.gg", "discord.media" }),

        new SensitiveAppDefinition(
            AppId: "steam",
            DisplayName: "Steam",
            ProcessNames: new[] { "steam.exe", "steamwebhelper.exe" },
            RegistryUninstallNameHints: new[] { "Steam" },
            RelativeAppDataPaths: Array.Empty<string>(),
            SensitiveSubPaths: new[] { "config", "ssfn*" },
            AllowedDomains: new[] { "steamcommunity.com", "steampowered.com", "steamgames.com", "steamcontent.com" }),

        new SensitiveAppDefinition(
            AppId: "chrome",
            DisplayName: "Google Chrome",
            ProcessNames: new[] { "chrome.exe" },
            RegistryUninstallNameHints: new[] { "Google Chrome" },
            RelativeAppDataPaths: new[] { "Google\\Chrome\\User Data" },
            SensitiveSubPaths: new[] { "Default\\Local Storage\\leveldb", "Default\\Login Data" },
            AllowedDomains: Array.Empty<string>()),

        new SensitiveAppDefinition(
            AppId: "edge",
            DisplayName: "Microsoft Edge",
            ProcessNames: new[] { "msedge.exe" },
            RegistryUninstallNameHints: new[] { "Microsoft Edge" },
            RelativeAppDataPaths: new[] { "Microsoft\\Edge\\User Data" },
            SensitiveSubPaths: new[] { "Default\\Local Storage\\leveldb", "Default\\Login Data" },
            AllowedDomains: Array.Empty<string>()),

        new SensitiveAppDefinition(
            AppId: "firefox",
            DisplayName: "Mozilla Firefox",
            ProcessNames: new[] { "firefox.exe" },
            RegistryUninstallNameHints: new[] { "Mozilla Firefox" },
            RelativeAppDataPaths: new[] { "Mozilla\\Firefox\\Profiles" },
            SensitiveSubPaths: new[] { "key4.db", "logins.json" },
            AllowedDomains: Array.Empty<string>()),

        new SensitiveAppDefinition(
            AppId: "epicgames",
            DisplayName: "Epic Games Launcher",
            ProcessNames: new[] { "EpicGamesLauncher.exe" },
            RegistryUninstallNameHints: new[] { "Epic Games Launcher" },
            RelativeAppDataPaths: new[] { "EpicGamesLauncher" },
            SensitiveSubPaths: new[] { "Saved\\Config" },
            AllowedDomains: Array.Empty<string>()),

        new SensitiveAppDefinition(
            AppId: "riotclient",
            DisplayName: "Riot Client",
            ProcessNames: new[] { "RiotClientServices.exe" },
            RegistryUninstallNameHints: new[] { "Riot Client" },
            RelativeAppDataPaths: new[] { "Riot Games" },
            SensitiveSubPaths: new[] { "Riot Client\\Data" },
            AllowedDomains: Array.Empty<string>()),

        new SensitiveAppDefinition(
            AppId: "amdsoftware",
            DisplayName: "AMD Software / Chipset Drivers",
            ProcessNames: new[]
            {
                "RadeonSoftware.exe", "CNext.exe", "AMDRSServ.exe",
                "atieclxx.exe", "atiesrxx.exe",
                "RyzenMaster.exe", "RyzenMasterService.exe",
            },
            RegistryUninstallNameHints: new[] { "AMD Software", "Radeon Software", "AMD Chipset Drivers", "AMD Ryzen Master" },
            RelativeAppDataPaths: new[] { "AMD" },
            SensitiveSubPaths: Array.Empty<string>(),
            AllowedDomains: new[] { "amd.com", "www.amd.com", "drivers.amd.com", "gaming.radeon.com", "radeon.com", "catalog.gpuopen.com" }),

        new SensitiveAppDefinition(
            AppId: "nvidiadriver",
            DisplayName: "NVIDIA App / GeForce Experience",
            ProcessNames: new[]
            {
                "nvcontainer.exe", "NVDisplay.Container.exe",
                "NVIDIA Share.exe", "NVIDIA Web Helper.exe", "nvsphelper64.exe",
            },
            RegistryUninstallNameHints: new[] { "NVIDIA Graphics Driver", "GeForce Experience", "NVIDIA App" },
            RelativeAppDataPaths: new[] { "NVIDIA Corporation", "NVIDIA" },
            SensitiveSubPaths: Array.Empty<string>(),
            AllowedDomains: new[] { "nvidia.com", "www.nvidia.com", "download.nvidia.com", "gfe.nvidia.com", "images.nvidia.com", "assets.nvidiagrid.net", "api.nvidia.com" }),

        new SensitiveAppDefinition(
            AppId: "inteldsa",
            DisplayName: "Intel Driver & Support Assistant",
            ProcessNames: new[] { "DSATray.exe", "IntelDSAService.exe", "esrv_svc.exe" },
            RegistryUninstallNameHints: new[] { "Intel(R) Driver & Support Assistant", "Intel Driver & Support Assistant" },
            RelativeAppDataPaths: new[] { "Intel\\Driver and Support Assistant" },
            SensitiveSubPaths: Array.Empty<string>(),
            AllowedDomains: new[] { "intel.com", "www.intel.com", "downloadmirror.intel.com", "dsadata.intel.com" }),
    };
}
