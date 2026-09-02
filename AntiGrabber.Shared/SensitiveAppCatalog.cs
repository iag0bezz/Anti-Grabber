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
    };
}
