rule Trojan_MSIL_Disstl_SA_2147773616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.SA!MTB"
        threat_id = "2147773616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile" ascii //weight: 1
        $x_1_2 = "https://canary.discord.com/api/webhooks/" ascii //weight: 1
        $x_1_3 = "https://cdn.discordapp.com/" ascii //weight: 1
        $x_1_4 = "http://sf3q2wrq34.ddns.net" ascii //weight: 1
        $x_1_5 = "GatonFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_QF_2147776160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.QF!MTB"
        threat_id = "2147776160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HogStealer" ascii //weight: 1
        $x_1_2 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 1
        $x_1_3 = "has been has been infected with HogStealer!" ascii //weight: 1
        $x_1_4 = "https://bit.ly/3987VpR" ascii //weight: 1
        $x_1_5 = "Hog Delivery Service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_A_2147778676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.A!MTB"
        threat_id = "2147778676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/s /t {0}" ascii //weight: 3
        $x_3_2 = "\\Programs\\Discord" ascii //weight: 3
        $x_3_3 = "\\tokens.txt" ascii //weight: 3
        $x_3_4 = "Local Storage\\leveldb" ascii //weight: 3
        $x_3_5 = "DiscordGrabber" ascii //weight: 3
        $x_3_6 = "MinecraftStealer" ascii //weight: 3
        $x_3_7 = "HasMinecraftInstalled" ascii //weight: 3
        $x_3_8 = "connection_trace.txt" ascii //weight: 3
        $x_3_9 = "FindTokensForPath" ascii //weight: 3
        $x_3_10 = "OpenAlgorithmProvider" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_A_2147778676_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.A!MTB"
        threat_id = "2147778676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "const child_process = require('child_process')" ascii //weight: 5
        $x_5_2 = "child_process.execSync(`{0}${{__dirname}}/{1}/Update.exe{2}`)" ascii //weight: 5
        $x_5_3 = "require(__dirname + '/{3}/inject.js')" ascii //weight: 5
        $x_4_4 = "mfa\\.(\\w|\\d|_|-){84}" ascii //weight: 4
        $x_4_5 = "(\\w|\\d){24}\\.(\\w|\\d|_|-){6}.(\\w|\\d|_|-){27}" ascii //weight: 4
        $x_3_6 = "discordmod.js" ascii //weight: 3
        $x_3_7 = "preload.js" ascii //weight: 3
        $x_3_8 = "inject.js" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Disstl_CA_2147778973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.CA!MTB"
        threat_id = "2147778973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 42 3e 11 04 28 ?? ?? ?? 06 17 8d ?? ?? ?? 01 13 06 11 06 16 1f 22 9d 11 06 6f ?? ?? ?? 0a 13 05 11 05 16 9a 0d 72 ?? ?? ?? 70 11 05 28 ?? ?? ?? 0a 13 04 03 2c 0a 09 6f ?? ?? ?? 0a 1f 3b}  //weight: 10, accuracy: Low
        $x_5_2 = "\\discord\\Local Storage\\leveldb\\" ascii //weight: 5
        $x_4_3 = "DiscordToken" ascii //weight: 4
        $x_3_4 = "ReadLogFile" ascii //weight: 3
        $x_3_5 = "\\LogCopy.txt" ascii //weight: 3
        $x_3_6 = "Software\\Growtopia" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Disstl_AWQ_2147779587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AWQ!MTB"
        threat_id = "2147779587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 41 16 0b 2b 0c 06 07 9a 6f ?? ?? ?? 0a 07 17 58 0b 07 06 8e 69 32 ee de 03}  //weight: 10, accuracy: Low
        $x_5_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Discord" ascii //weight: 5
        $x_4_3 = "index.js" ascii //weight: 4
        $x_4_4 = "discord_desktop_core" ascii //weight: 4
        $x_4_5 = "discord_modules" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Disstl_AMD_2147779928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AMD!MTB"
        threat_id = "2147779928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 13 06 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 58 6f ?? ?? ?? 0a 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 25 0b 15 33 dd}  //weight: 10, accuracy: Low
        $x_5_2 = "Discord" ascii //weight: 5
        $x_5_3 = "\\Growtopia\\save.dat" ascii //weight: 5
        $x_4_4 = "GetAllNetworkInterfaces" ascii //weight: 4
        $x_4_5 = "UploadFile" ascii //weight: 4
        $x_3_6 = "WebHook" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Disstl_ACH_2147781171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ACH!MTB"
        threat_id = "2147781171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Discord" ascii //weight: 3
        $x_3_2 = "\\discordcanary" ascii //weight: 3
        $x_3_3 = "\\discordptb" ascii //weight: 3
        $x_2_4 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" ascii //weight: 2
        $x_2_5 = "mfa\\.[\\w-]{84}" ascii //weight: 2
        $x_2_6 = "PostToken" ascii //weight: 2
        $x_2_7 = "httpClient" ascii //weight: 2
        $x_2_8 = "\\Local Storage\\leveldb" ascii //weight: 2
        $x_2_9 = "Discord Token Grabber" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AT_2147781320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AT!MTB"
        threat_id = "2147781320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 2b 3e 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 6f ?? ?? ?? 0a 16 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 1f 3b 2e 0c 08 6f ?? ?? ?? 0a 1f 58 fe 01 2b 01 17 2c 04 08 0a de 24 07}  //weight: 10, accuracy: Low
        $x_5_2 = "kooH niatpaC" ascii //weight: 5
        $x_5_3 = "bdlevel\\egarotS lacoL\\drocsid" ascii //weight: 5
        $x_3_4 = "([A-Za-z0-9_\\./\\\\-]*)" ascii //weight: 3
        $x_2_5 = "bdl." ascii //weight: 2
        $x_2_6 = "gol." ascii //weight: 2
        $x_2_7 = "bdlevel\\egarotS lacoL\\yranacdrocsid" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AVF_2147781325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AVF!MTB"
        threat_id = "2147781325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "index.js" ascii //weight: 5
        $x_5_2 = "DiscordBuild" ascii //weight: 5
        $x_5_3 = "GetDiscordPath" ascii //weight: 5
        $x_5_4 = "Inject" ascii //weight: 5
        $x_4_5 = "DiscordCanary" ascii //weight: 4
        $x_4_6 = "BuildToString" ascii //weight: 4
        $x_4_7 = "discord_desktop_core" ascii //weight: 4
        $x_4_8 = "\\d.\\d.\\d{2}(\\d|$)" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_DAC_2147781332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.DAC!MTB"
        threat_id = "2147781332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Discord" ascii //weight: 5
        $x_4_2 = "PrincipalWorker" ascii //weight: 4
        $x_4_3 = "GetOsFullname" ascii //weight: 4
        $x_4_4 = "GetHardDriveSerialNumber" ascii //weight: 4
        $x_4_5 = "DeleteValueFromRegistry" ascii //weight: 4
        $x_4_6 = "capGetDriverDescriptionA" ascii //weight: 4
        $x_4_7 = "CameraExists" ascii //weight: 4
        $x_4_8 = "StartupCopiedAssemblyFileStream" ascii //weight: 4
        $x_4_9 = "MutexName" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_FAC_2147781752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.FAC!MTB"
        threat_id = "2147781752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "hjiweykaksd" ascii //weight: 5
        $x_5_2 = "PasswordDeriveBytes" ascii //weight: 5
        $x_5_3 = "Discord" ascii //weight: 5
        $x_4_4 = "avatar_url" ascii //weight: 4
        $x_4_5 = "Data\\liblang.dll" ascii //weight: 4
        $x_4_6 = "LOG.DLL" ascii //weight: 4
        $x_4_7 = "BFWA" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_4_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Disstl_AH_2147781934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AH!MTB"
        threat_id = "2147781934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ttZID1v0v1TqMWhYdkJXb61/qNdz/g+aMmf8XEyyrsqfmkke0DHfIrYxUeyEbrB02o" wide //weight: 3
        $x_3_2 = "/C /stext" ascii //weight: 3
        $x_3_3 = "discord" ascii //weight: 3
        $x_3_4 = "GetAllNetworkInterfaces" ascii //weight: 3
        $x_3_5 = "GetPhysicalAddress" ascii //weight: 3
        $x_3_6 = "Webhook" ascii //weight: 3
        $x_3_7 = "avatar_url" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_W_2147782407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.W!MTB"
        threat_id = "2147782407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "PitFuckerV1" ascii //weight: 3
        $x_3_2 = "discordapp" ascii //weight: 3
        $x_3_3 = "[Owner] PatP" ascii //weight: 3
        $x_3_4 = "GetRoot" ascii //weight: 3
        $x_3_5 = "DownloadString" ascii //weight: 3
        $x_3_6 = "avatar_url" ascii //weight: 3
        $x_3_7 = "SendMeResults" ascii //weight: 3
        $x_3_8 = "DataGrabButton" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AM_2147783663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AM!MTB"
        threat_id = "2147783663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 07 6f 3c 00 00 0a 1f 3b 2e 0c 07 6f 3c 00 00 0a 1f 58 fe 01 2b 01}  //weight: 10, accuracy: High
        $x_3_2 = "discord_modules" ascii //weight: 3
        $x_3_3 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 3
        $x_3_4 = "bdlevel\\egarotS lacoL\\drocsid" ascii //weight: 3
        $x_3_5 = "bdlevel\\egarotS lacoL\\btpdrocsid" ascii //weight: 3
        $x_3_6 = "lru_ratava" ascii //weight: 3
        $x_3_7 = "PostAsync" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AM_2147783663_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AM!MTB"
        threat_id = "2147783663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Grando *kisses you on the cheek*" wide //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "discord.com/api/users/@me" wide //weight: 1
        $x_1_4 = "icanhazip.com" wide //weight: 1
        $x_1_5 = "fiddler" wide //weight: 1
        $x_1_6 = "httpdebuggerui" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_B_2147784090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.B!MTB"
        threat_id = "2147784090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" ascii //weight: 3
        $x_3_2 = "mfa\\.[\\w-]{84}" ascii //weight: 3
        $x_3_3 = "Discord Climax Grabber" ascii //weight: 3
        $x_3_4 = "WeDemBoyz" ascii //weight: 3
        $x_3_5 = "\\Discord" ascii //weight: 3
        $x_3_6 = "\\discordcanary" ascii //weight: 3
        $x_3_7 = "FormUrlEncodedContent" ascii //weight: 3
        $x_3_8 = "PostAsync" ascii //weight: 3
        $x_3_9 = "avatarUrl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_B_2147784090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.B!MTB"
        threat_id = "2147784090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {1f 3b 2e 0c 08 6f 2d 00 00 0a 1f 58 fe 01 2b 01 17 0d 09 2c 05 08 13 04 de 29 00 06}  //weight: 10, accuracy: High
        $x_3_2 = "Discord Token Grabber" ascii //weight: 3
        $x_3_3 = "DownloadString" ascii //weight: 3
        $x_3_4 = "avatar_url" ascii //weight: 3
        $x_3_5 = "discordptb\\Local Storage\\leveldb" ascii //weight: 3
        $x_3_6 = "discord\\Local Storage\\leveldb" ascii //weight: 3
        $x_3_7 = "RemoveAccessRule" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AKL_2147784688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AKL!MTB"
        threat_id = "2147784688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "C:/temp/Passwords.txt" ascii //weight: 3
        $x_3_2 = "C:/temp/System_INFO.txt" ascii //weight: 3
        $x_3_3 = "sendhookfile" ascii //weight: 3
        $x_3_4 = "StealerBin" ascii //weight: 3
        $x_3_5 = "discordapp" ascii //weight: 3
        $x_3_6 = "C:/temp/finalres.vbs" ascii //weight: 3
        $x_3_7 = "WebBrowserPassView" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AF_2147785042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AF!MTB"
        threat_id = "2147785042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" ascii //weight: 3
        $x_3_2 = "mfa\\.[\\w-]{84}" ascii //weight: 3
        $x_3_3 = "discordcanary" ascii //weight: 3
        $x_3_4 = "Discord Token Grabber" ascii //weight: 3
        $x_3_5 = "GrabberBuilderCODE" ascii //weight: 3
        $x_3_6 = "Webhook" ascii //weight: 3
        $x_3_7 = "SendToken" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_VX_2147785244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.VX!MTB"
        threat_id = "2147785244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments/696080024742395914/718483498947838063/beetlejuice-1.jpg" ascii //weight: 1
        $x_1_2 = "Report from Candy Grabber" ascii //weight: 1
        $x_1_3 = "ipv4bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_4 = "Tokens" ascii //weight: 1
        $x_1_5 = "avatar_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ASX_2147786460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ASX!MTB"
        threat_id = "2147786460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "app-\\d\\.\\d{1,}\\.\\d{1,}" ascii //weight: 3
        $x_3_2 = "discord_desktop_core" ascii //weight: 3
        $x_3_3 = "disable_2fa" ascii //weight: 3
        $x_3_4 = "--processStart" ascii //weight: 3
        $x_3_5 = "CheckTokens" ascii //weight: 3
        $x_3_6 = "(\\w|\\d){24}\\.(\\w|\\d|_|-){6}.(\\w|\\d|_|-){27}" ascii //weight: 3
        $x_3_7 = "webhook" ascii //weight: 3
        $x_3_8 = "PostAsync" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AX_2147786529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AX!MTB"
        threat_id = "2147786529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {20 00 40 01 00 8d 12 00 00 01 0a 2b 09 03 06 16 07 6f 13 00 00 0a 02 06 16 06 8e 69 6f 14 00 00 0a 25 0b 2d e8}  //weight: 10, accuracy: High
        $x_3_2 = "costura.costura.pdb" ascii //weight: 3
        $x_3_3 = "Nitro Generator_ProcessedByFody" ascii //weight: 3
        $x_3_4 = "isAttached" ascii //weight: 3
        $x_3_5 = "requestedAssemblyName" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ASD_2147787519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ASD!MTB"
        threat_id = "2147787519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "IYKZG2NU11MIKP1NKTRSBSZW60" ascii //weight: 3
        $x_3_2 = "G328ISKFDEBH6TAOJFIZ" ascii //weight: 3
        $x_3_3 = "M4Z5MB9TGURP2FRZPZI2" ascii //weight: 3
        $x_3_4 = "emanresu" ascii //weight: 3
        $x_3_5 = "discord" ascii //weight: 3
        $x_3_6 = "bdlevel\\egarotS lacoL\\drocsid" ascii //weight: 3
        $x_3_7 = "GetAccessControl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ANJ_2147787593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ANJ!MTB"
        threat_id = "2147787593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DeleteLocalStorage" ascii //weight: 3
        $x_3_2 = "KillProcess" ascii //weight: 3
        $x_3_3 = "discord_desktop_core" ascii //weight: 3
        $x_3_4 = "DiscordFucker" ascii //weight: 3
        $x_3_5 = "/injector/permanant?webhook=" ascii //weight: 3
        $x_3_6 = "index.js" ascii //weight: 3
        $x_3_7 = "DiscordPTB" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_EF_2147794112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.EF!MTB"
        threat_id = "2147794112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "discord_desktop_core\\index.js" ascii //weight: 3
        $x_3_2 = "DiscordPTB" ascii //weight: 3
        $x_3_3 = "DiscordCanary" ascii //weight: 3
        $x_3_4 = "firstrun" ascii //weight: 3
        $x_3_5 = "hookUrl" ascii //weight: 3
        $x_3_6 = "Local Settings\\Application Data\\Discord" ascii //weight: 3
        $x_3_7 = "GetFolderPath" ascii //weight: 3
        $x_3_8 = "wang2.pdb" ascii //weight: 3
        $x_3_9 = "Replace" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_EM_2147794126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.EM!MTB"
        threat_id = "2147794126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 02 28 26 00 00 06 25 20 00 80 00 00 5f 20 00 80 00 00 33 04 06 17 60 0a 17 5f 17 33 04 06 18 60 0a 06 2a}  //weight: 10, accuracy: High
        $x_3_2 = "keyLogger" ascii //weight: 3
        $x_3_3 = "Spyware" ascii //weight: 3
        $x_3_4 = "IsKeyToggled" ascii //weight: 3
        $x_3_5 = "GetKeyState" ascii //weight: 3
        $x_3_6 = "isKeyDown" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_QW_2147794341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.QW!MTB"
        threat_id = "2147794341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "discord_desktop_core\\index.js" ascii //weight: 3
        $x_3_2 = "DiscordPTB" ascii //weight: 3
        $x_3_3 = "DiscordCanary" ascii //weight: 3
        $x_3_4 = "wang.Properties.Resources" ascii //weight: 3
        $x_3_5 = "GetFolderPath" ascii //weight: 3
        $x_3_6 = "your_hook" ascii //weight: 3
        $x_3_7 = "process.env.hook" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_TV_2147794360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.TV!MTB"
        threat_id = "2147794360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 26 09 16 28 0a 00 00 0a 20 68 dc 2d 7d 61 1f 64 59 13 04 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 1b 59 20 2f 6a f2 1c 61 13 05 07 11 04 6a 16 6f}  //weight: 1, accuracy: High
        $x_1_2 = "StanGrabber.exe" ascii //weight: 1
        $x_1_3 = "DiscordCanary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_C_2147794436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.C!MTB"
        threat_id = "2147794436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\AppData\\Roaming\\Discord" ascii //weight: 3
        $x_3_2 = "ytpmE" ascii //weight: 3
        $x_3_3 = "sserddapiymsitahw" ascii //weight: 3
        $x_3_4 = "enoyreve" ascii //weight: 3
        $x_3_5 = "avatar_url" ascii //weight: 3
        $x_3_6 = "SendMeResults" ascii //weight: 3
        $x_3_7 = "drocsid" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_QQ_2147795241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.QQ!MTB"
        threat_id = "2147795241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 3
        $x_3_2 = "discord_modules" ascii //weight: 3
        $x_3_3 = "index.js" ascii //weight: 3
        $x_3_4 = "emanresu" ascii //weight: 3
        $x_3_5 = "tluafeD\\ataD resU\\elahW revaN\\revaN" ascii //weight: 3
        $x_3_6 = "yranacdrocsid" ascii //weight: 3
        $x_3_7 = "btpdrocsid" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_QA_2147795335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.QA!MTB"
        threat_id = "2147795335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "StealerBin" ascii //weight: 3
        $x_3_2 = "C:/temp/Passwords.txt" ascii //weight: 3
        $x_3_3 = "Browser Password" ascii //weight: 3
        $x_3_4 = "C:/temp/finalres.vbs" ascii //weight: 3
        $x_3_5 = "SendSysInfo" ascii //weight: 3
        $x_3_6 = "C:/temp/System_INFO.txt" ascii //weight: 3
        $x_3_7 = "sendhookfile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AV_2147796650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AV!MTB"
        threat_id = "2147796650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "azula_logger" ascii //weight: 3
        $x_3_2 = "KillDiscord" ascii //weight: 3
        $x_3_3 = "sendDiscordWebhook" ascii //weight: 3
        $x_3_4 = "Zedin logger" ascii //weight: 3
        $x_3_5 = "\\discord\\Local Storage\\leveldb\\" ascii //weight: 3
        $x_3_6 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii //weight: 3
        $x_3_7 = "GetWinInfo" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AD_2147797736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AD!MTB"
        threat_id = "2147797736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 2c 63 00 03 8e 69 d1 0b 07 20 ff 00 00 00 fe 02 0d 09 2c 28 00 07 19 58 8d ?? ?? ?? 01 0c 08 16 16 9c 08 17 07 d2 9c 08 18 07 1e 63 d2 9c 03 16 08 19 07 28 ?? ?? ?? 0a 00 00 2b 1b 00 07 17 58 8d ?? ?? ?? 01 0c 08 16 07 d2 9c 03 16 08 17 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AD_2147797736_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AD!MTB"
        threat_id = "2147797736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MB_Grabber" ascii //weight: 3
        $x_3_2 = "DiscordDevelopment" ascii //weight: 3
        $x_3_3 = "getInfo" ascii //weight: 3
        $x_3_4 = "(mfa\\.[a-z0-9_-]{20,})|([a-z0-9_-]{23,28}\\.[a-z0-9_-]{6,7}\\.[a-z0-9_-]{27})" ascii //weight: 3
        $x_3_5 = "WebhookMessage" ascii //weight: 3
        $x_3_6 = "get_avatar_url" ascii //weight: 3
        $x_3_7 = "doTheEmergencyThing" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_CB_2147808321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.CB!MTB"
        threat_id = "2147808321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please Go To #downloads In The Discord And Download The New Verison" ascii //weight: 1
        $x_1_2 = "https://pastebin.com/raw" ascii //weight: 1
        $x_1_3 = "$c78e5757-4597-487a-bcea-9538403d96e6" ascii //weight: 1
        $x_1_4 = "YOU CAN GET BANNED FROM THE BOT USING THIS BE SAFE" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "discord.gg" ascii //weight: 1
        $x_1_7 = "C:\\Users\\dawns\\source\\repos\\Zxno's Discord Tools\\obj\\Debug\\Zxno's Discord Tools.pdb" ascii //weight: 1
        $x_1_8 = "DiscordWebhookProfile" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_CF_2147808324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.CF!MTB"
        threat_id = "2147808324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dont share this stealer anywhere" ascii //weight: 1
        $x_1_2 = "dcd.exe" ascii //weight: 1
        $x_1_3 = "https://eternitypr.net" ascii //weight: 1
        $x_1_4 = "Growtopia\\save.dat" ascii //weight: 1
        $x_1_5 = "webhookurl" ascii //weight: 1
        $x_1_6 = "encrypted_key" ascii //weight: 1
        $x_1_7 = "Sending info to Eternity" ascii //weight: 1
        $x_1_8 = "growtopia1.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_CL_2147808434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.CL!MTB"
        threat_id = "2147808434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://discord.gg/emRvZJGhBS" ascii //weight: 1
        $x_1_2 = "https://discordapp.com/api/v6/users/@me" ascii //weight: 1
        $x_1_3 = "$8f1be126-9555-4515-8450-7b1b72923dbf" ascii //weight: 1
        $x_1_4 = "http://ipinfo.io/ip" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "https://mega.nz/folder" ascii //weight: 1
        $x_1_7 = "USER GOT FUCKED BY BLACK-HAWK" ascii //weight: 1
        $x_1_8 = "https://discord.com/api/webhooks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_FB_2147808477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.FB!MTB"
        threat_id = "2147808477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Local Storage\\leveldb" ascii //weight: 3
        $x_3_2 = "FindTokens" ascii //weight: 3
        $x_3_3 = "\\discordcanary" ascii //weight: 3
        $x_3_4 = "GetChunks" ascii //weight: 3
        $x_3_5 = "@me/billing/payments" ascii //weight: 3
        $x_3_6 = "DownloadString" ascii //weight: 3
        $x_3_7 = "size=512" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_BK_2147809805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.BK!MTB"
        threat_id = "2147809805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 1f 0f 59 8d ?? ?? ?? ?? 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 ?? ?? ?? ?? 1f 10 8d ?? ?? ?? ?? 0c 07 8e 69 08 8e 69 59 8d ?? ?? ?? ?? 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28}  //weight: 1, accuracy: Low
        $x_1_2 = {07 16 09 16 07 8e 69 08 8e 69 59 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 04 28 ?? ?? ?? ?? 11 04 03 06 14 09 08 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 05 11 05 13 06 de 06}  //weight: 1, accuracy: Low
        $x_1_3 = "DecryptWithKey" ascii //weight: 1
        $x_1_4 = "StealPasswords" ascii //weight: 1
        $x_1_5 = "Error in Anti Debug, Check Debug" ascii //weight: 1
        $x_1_6 = "virtualbox" ascii //weight: 1
        $x_1_7 = "https://ip4.seeip.org" ascii //weight: 1
        $x_1_8 = "Unable to decrypt" ascii //weight: 1
        $x_1_9 = "encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_GLT_2147810915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.GLT!MTB"
        threat_id = "2147810915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadString" ascii //weight: 1
        $x_1_2 = "https://dis{0}d.com/api/webhooks/899278272179863642/CrPrQqbWb4570Liu_vjmMrD629ImSKwpErk9b88TdmewCdhF8z_IWH1L3AmqV5mHpPkX" ascii //weight: 1
        $x_1_3 = "https://discordapp.com/api/v6/users/@me" ascii //weight: 1
        $x_1_4 = "https://discordapp.com/api/v6/users/@me/billing/payments" ascii //weight: 1
        $x_1_5 = "https://discordapp.com/api/v6/users/@me/guilds" ascii //weight: 1
        $x_1_6 = "https://discordapp.com/api/v6/users/@me/relationships" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_AN_2147814343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.AN!MTB"
        threat_id = "2147814343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sir_I_am_illusioning_or_you_reading_me" wide //weight: 1
        $x_1_2 = "encrypted_key" wide //weight: 1
        $x_1_3 = "Some retard who thinks he can reverse this application" wide //weight: 1
        $x_1_4 = "Select * from Win32_ComputerSystem" wide //weight: 1
        $x_1_5 = "fpPk11SdrDecrypt" ascii //weight: 1
        $x_1_6 = "encryptedUsername" wide //weight: 1
        $x_1_7 = "uggcf://jjj.qebcobk.pbz/bnhgu2/nhgubevmr" wide //weight: 1
        $x_1_8 = "VirtualBox" wide //weight: 1
        $x_1_9 = "VirtualProtect" ascii //weight: 1
        $x_1_10 = "VMware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ABZ_2147827756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ABZ!MTB"
        threat_id = "2147827756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 09 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 2b 06 72 ?? ?? ?? 70 09 17 8d ?? ?? ?? 01 13 04 11 04 16 1f 22 9d 11 04 6f ?? ?? ?? 0a 1d 9a 44 00 07 72 ?? ?? ?? 70 02 6f ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 08 6f 3b}  //weight: 4, accuracy: Low
        $x_1_2 = "CheckDebugMode" ascii //weight: 1
        $x_1_3 = "CheckDiscordToken" ascii //weight: 1
        $x_1_4 = "CheckRoblox" ascii //weight: 1
        $x_1_5 = "CheckCopiedText" ascii //weight: 1
        $x_1_6 = "CreditCards" ascii //weight: 1
        $x_1_7 = "Cookies" ascii //weight: 1
        $x_1_8 = "DetectedBankingServices" ascii //weight: 1
        $x_1_9 = "CreateDownloadLink" ascii //weight: 1
        $x_1_10 = "GetWifiPassword" ascii //weight: 1
        $x_1_11 = "StealVPN" ascii //weight: 1
        $x_1_12 = "GetAllNetworkInterfaces" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ABJC_2147839121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ABJC!MTB"
        threat_id = "2147839121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 07 16 73 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 09 28 ?? ?? ?? 06 09 16 6a 6f ?? ?? ?? 0a 09 13 04 de 1c 08 2c 06 08 6f ?? ?? ?? 0a dc 34 00 06 02 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_3 = "Timer_Resolution.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ADL_2147845009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ADL!MTB"
        threat_id = "2147845009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 02 7b 04 00 00 04 6f ?? ?? ?? 0a a2 25 17 02 7b 03 00 00 04 6f ?? ?? ?? 0a a2 25 18 02 7b 09 00 00 04 6f ?? ?? ?? 0a a2 25 19 02 7b 03 00 00 04 6f ?? ?? ?? 0a a2 25 1a 72 31 00 00 70 a2}  //weight: 2, accuracy: Low
        $x_1_2 = "Discord Token Grabber, is a Builder that lets you create payloads to gain Tokens from users" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ADS_2147847999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ADS!MTB"
        threat_id = "2147847999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 0a 73 14 00 00 0a 0b 07 6f ?? ?? ?? 0a 72 f6 00 00 70 72 10 01 00 70 6f ?? ?? ?? 0a 00 72 32 01 00 70 02 72 4e 01 00 70 28 ?? ?? ?? 0a 0c 07 06 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Temp\\Mahesh.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ADS_2147847999_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ADS!MTB"
        threat_id = "2147847999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 07 6f ?? ?? ?? 0a 72 c4 01 00 70 72 de 01 00 70 6f ?? ?? ?? 0a 00 72 00 02 00 70 02 72 1c 02 00 70 28 ?? ?? ?? 0a 0c 07 06}  //weight: 2, accuracy: Low
        $x_1_2 = "\\adria\\Downloads\\Discord-Grabber-main\\Grabber\\obj\\Debug\\Program.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ADI_2147849697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ADI!MTB"
        threat_id = "2147849697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 25 17 28 ?? ?? ?? 0a a2 25 18 72 50 01 00 70 a2 25 19 02 7b 05 00 00 04 a2 25 1a 72 54 01 00 70 a2 28 ?? ?? ?? 0a 0c 07 06}  //weight: 2, accuracy: Low
        $x_1_2 = "\\debug\\source\\repos\\PcCleaner\\PcCleaner\\obj\\Debug\\PcCleaner.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ADI_2147849697_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ADI!MTB"
        threat_id = "2147849697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 80 00 00 00 6f 57 00 00 0a 00 06 20 00 01 00 00 6f 58 00 00 0a 00 06 17 6f 59 00 00 0a 00 06 18 6f 5a 00 00 0a 00 06 28 5b 00 00 0a 03 6f 5c 00 00 0a 6f 5d 00 00 0a 00 06 28 5b 00 00 0a 04 6f 5c 00 00 0a 6f 5e 00 00 0a 00 06 06 6f 5f 00 00 0a 06 6f 60 00 00 0a 6f 68 00 00 0a 0b 7e 69 00 00 0a 0c 02 28}  //weight: 2, accuracy: High
        $x_1_2 = "Fucked.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disstl_ADI_2147849697_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disstl.ADI!MTB"
        threat_id = "2147849697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 07 09 16 11 05 6f 2c 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8}  //weight: 2, accuracy: High
        $x_2_2 = {08 1f 53 58 0c 00 73 ?? 00 00 0a 7e ?? 00 00 0a 8e 20 91 d2 00 00 58 7e ?? 00 00 0a 8e 20 aa d5 00 00 58 fe 1c 10 00 00 01 1f 41 58 28}  //weight: 2, accuracy: Low
        $x_1_3 = "DiscordResolver.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

