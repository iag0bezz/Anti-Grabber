namespace AntiGrabber.Shared;

public sealed record SensitiveAppDefinition(
    string AppId,
    string DisplayName,
    string[] ProcessNames,
    string[] RegistryUninstallNameHints,
    string[] RelativeAppDataPaths,
    string[] SensitiveSubPaths,
    string[] AllowedDomains,
    // Dados de login (token de sessão): processo de fora que lê isso fica bloqueado na
    // rede pra QUALQUER domínio por um tempo — stealer manda pra servidor próprio também.
    bool AccountData = false,
    // Launcher que roda em Java (TLauncher, ATLauncher): o dono é um javaw.exe, o mesmo
    // nome do jogo cheio de mods. Só conta como dono se a linha de comando citar o launcher.
    string[]? OwnerCommandLineHints = null);

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
        // Minecraft: sem AllowedDomains de propósito. O javaw do jogo precisa falar com
        // sessionserver.mojang.com/api.minecraftservices.com pra entrar em servidor; domínio
        // no catálogo vira sensível e code host nunca é liberado pelo nome — quebraria o
        // multiplayer. A proteção aqui é a leitura dos arquivos de conta (AccountData).
        // Verificados em máquina real: oficial (MS Store), Prism, Modrinth. Os demais
        // seguem o caminho documentado pelos launchers.
        new SensitiveAppDefinition(
            AppId: "minecraft",
            DisplayName: "Minecraft Launcher",
            ProcessNames: new[] { "MinecraftLauncher.exe", "Minecraft.exe" },
            RegistryUninstallNameHints: new[] { "Minecraft Launcher" },
            RelativeAppDataPaths: new[] { ".minecraft" },
            SensitiveSubPaths: new[] { "launcher_accounts*.json", "launcher_msa_credentials*" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "tlauncher",
            DisplayName: "TLauncher",
            ProcessNames: new[] { "TLauncher.exe" },
            RegistryUninstallNameHints: new[] { "TLauncher" },
            RelativeAppDataPaths: new[] { ".minecraft" },
            SensitiveSubPaths: new[] { "TlauncherProfiles.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true,
            OwnerCommandLineHints: new[] { "tlauncher" }),

        new SensitiveAppDefinition(
            AppId: "prismlauncher",
            DisplayName: "Prism Launcher",
            ProcessNames: new[] { "prismlauncher.exe" },
            RegistryUninstallNameHints: new[] { "Prism Launcher" },
            RelativeAppDataPaths: new[] { "PrismLauncher" },
            SensitiveSubPaths: new[] { "accounts.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "polymc",
            DisplayName: "PolyMC",
            ProcessNames: new[] { "polymc.exe" },
            RegistryUninstallNameHints: new[] { "PolyMC" },
            RelativeAppDataPaths: new[] { "PolyMC" },
            SensitiveSubPaths: new[] { "accounts.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        // Portátil: sem pasta em AppData, os dados ficam ao lado do executável.
        new SensitiveAppDefinition(
            AppId: "multimc",
            DisplayName: "MultiMC",
            ProcessNames: new[] { "MultiMC.exe" },
            RegistryUninstallNameHints: new[] { "MultiMC" },
            RelativeAppDataPaths: Array.Empty<string>(),
            SensitiveSubPaths: new[] { "accounts.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "modrinth",
            DisplayName: "Modrinth App",
            ProcessNames: new[] { "Modrinth App.exe" },
            RegistryUninstallNameHints: new[] { "Modrinth App" },
            RelativeAppDataPaths: new[] { "ModrinthApp" },
            SensitiveSubPaths: new[] { "app.db*" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "curseforge",
            DisplayName: "CurseForge (Minecraft)",
            ProcessNames: new[] { "CurseForge.exe", "MinecraftLauncher.exe", "Minecraft.exe" },
            RegistryUninstallNameHints: new[] { "CurseForge" },
            RelativeAppDataPaths: new[] { "curseforge\\minecraft\\Install" },
            SensitiveSubPaths: new[] { "launcher_accounts*.json", "launcher_msa_credentials*" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "atlauncher",
            DisplayName: "ATLauncher",
            ProcessNames: new[] { "ATLauncher.exe" },
            RegistryUninstallNameHints: new[] { "ATLauncher" },
            RelativeAppDataPaths: Array.Empty<string>(),
            SensitiveSubPaths: new[] { "configs\\accounts.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true,
            OwnerCommandLineHints: new[] { "atlauncher" }),

        new SensitiveAppDefinition(
            AppId: "lunarclient",
            DisplayName: "Lunar Client",
            ProcessNames: new[] { "Lunar Client.exe" },
            RegistryUninstallNameHints: new[] { "Lunar Client" },
            RelativeAppDataPaths: new[] { ".lunarclient" },
            SensitiveSubPaths: new[] { "settings\\game\\accounts.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "feather",
            DisplayName: "Feather Client",
            ProcessNames: new[] { "Feather Launcher.exe", "Feather.exe" },
            RegistryUninstallNameHints: new[] { "Feather" },
            RelativeAppDataPaths: new[] { ".feather" },
            SensitiveSubPaths: new[] { "accounts.json" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),

        new SensitiveAppDefinition(
            AppId: "badlion",
            DisplayName: "Badlion Client",
            ProcessNames: new[] { "Badlion Client.exe" },
            RegistryUninstallNameHints: new[] { "Badlion Client" },
            RelativeAppDataPaths: new[] { "Badlion Client" },
            SensitiveSubPaths: new[] { "accounts*" },
            AllowedDomains: Array.Empty<string>(),
            AccountData: true),
    };
}
