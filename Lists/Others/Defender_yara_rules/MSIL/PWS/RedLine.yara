rule PWS_MSIL_RedLine_GG_2147772078_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "RedLine.Client" ascii //weight: 15
        $x_1_2 = "Screenshot" ascii //weight: 1
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "CreditCard" ascii //weight: 1
        $x_1_5 = "encryptedPassword" ascii //weight: 1
        $x_1_6 = "Wallet" ascii //weight: 1
        $x_1_7 = "Parse" ascii //weight: 1
        $x_1_8 = "OpenVPN" ascii //weight: 1
        $x_1_9 = "RunPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "RedLine." ascii //weight: 15
        $x_1_2 = "Screenshot" ascii //weight: 1
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "GrabFTP" ascii //weight: 1
        $x_1_5 = "GrabVPN" ascii //weight: 1
        $x_1_6 = "Telegram" ascii //weight: 1
        $x_1_7 = "Credentials" ascii //weight: 1
        $x_1_8 = "CreditCards" ascii //weight: 1
        $x_1_9 = "Capture" ascii //weight: 1
        $x_1_10 = "ColdWallet" ascii //weight: 1
        $x_1_11 = "encryptedPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RedLine.Reburn" ascii //weight: 10
        $x_1_2 = "BlacklistedIP" ascii //weight: 1
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "GrabFTP" ascii //weight: 1
        $x_1_5 = "WalletName" ascii //weight: 1
        $x_1_6 = "GrabTelegram" ascii //weight: 1
        $x_1_7 = "Credentials" ascii //weight: 1
        $x_1_8 = "CreditCards" ascii //weight: 1
        $x_1_9 = "CaptureScreen" ascii //weight: 1
        $x_1_10 = "AntivirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "RedLine.Reburn" ascii //weight: 15
        $x_1_2 = "Screenshot" ascii //weight: 1
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "GrabFTP" ascii //weight: 1
        $x_1_5 = "GrabVPN" ascii //weight: 1
        $x_1_6 = "Telegram" ascii //weight: 1
        $x_1_7 = "Credentials" ascii //weight: 1
        $x_1_8 = "CreditCards" ascii //weight: 1
        $x_1_9 = "Capture" ascii //weight: 1
        $x_1_10 = "ColdWallet" ascii //weight: 1
        $x_1_11 = "encryptedPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_4
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "RedLine." ascii //weight: 15
        $x_1_2 = "Screenshot" ascii //weight: 1
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "Telegram" ascii //weight: 1
        $x_1_5 = "Credentials" ascii //weight: 1
        $x_1_6 = "Capture" ascii //weight: 1
        $x_1_7 = "CreditCard" ascii //weight: 1
        $x_1_8 = "encryptedPassword" ascii //weight: 1
        $x_1_9 = "sucks" ascii //weight: 1
        $x_1_10 = "ParseBrowsers" ascii //weight: 1
        $x_1_11 = "Grab" ascii //weight: 1
        $x_1_12 = "Wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_5
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "Telegram" ascii //weight: 10
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "Password" ascii //weight: 1
        $x_1_5 = "<geoplugin" ascii //weight: 1
        $x_1_6 = "wallet" ascii //weight: 1
        $x_1_7 = "GameLauncher" ascii //weight: 1
        $x_1_8 = "Discord" ascii //weight: 1
        $x_1_9 = "<Scan" ascii //weight: 1
        $x_1_10 = "Browsers" ascii //weight: 1
        $x_1_11 = "NordVPN" ascii //weight: 1
        $x_1_12 = "Chr_0_M_e" ascii //weight: 1
        $x_1_13 = "SELECT * FROM" ascii //weight: 1
        $x_1_14 = "*ssfn*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_6
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "Telegram" ascii //weight: 10
        $x_1_3 = "Download" ascii //weight: 1
        $x_1_4 = "Password" ascii //weight: 1
        $x_1_5 = "<geoplugin" ascii //weight: 1
        $x_1_6 = "wallet" ascii //weight: 1
        $x_1_7 = "GameChatFile" ascii //weight: 1
        $x_1_8 = "Blocked" ascii //weight: 1
        $x_1_9 = "ProtonVPN" ascii //weight: 1
        $x_1_10 = "api.ip.sb/geoip" ascii //weight: 1
        $x_1_11 = "SELECT * FROM Win32_" ascii //weight: 1
        $x_1_12 = "0 Mb or " ascii //weight: 1
        $x_1_13 = "<Scan>" ascii //weight: 1
        $x_1_14 = "Discord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_7
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = "RedLine.Client" ascii //weight: 15
        $x_1_2 = "Download" ascii //weight: 1
        $x_1_3 = "encryptedPassword" ascii //weight: 1
        $x_1_4 = "RunPE" ascii //weight: 1
        $x_1_5 = "Parse" ascii //weight: 1
        $x_1_6 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_8 = "Wallet" ascii //weight: 1
        $x_1_9 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_10 = "RedLine.Reburn" ascii //weight: 1
        $x_1_11 = "<geoplugin" ascii //weight: 1
        $x_1_12 = "SUCK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_8
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "Telegram" ascii //weight: 10
        $x_1_3 = "Parse" ascii //weight: 1
        $x_1_4 = "Download" ascii //weight: 1
        $x_1_5 = "Password" ascii //weight: 1
        $x_1_6 = "<geoplugin" ascii //weight: 1
        $x_1_7 = "Electrum" ascii //weight: 1
        $x_1_8 = "wallet" ascii //weight: 1
        $x_1_9 = "api.ipify.org" ascii //weight: 1
        $x_1_10 = "//ipinfo.io/ip%appdata%" ascii //weight: 1
        $x_1_11 = "Coin" ascii //weight: 1
        $x_1_12 = "GameChatFile" ascii //weight: 1
        $x_1_13 = "Blocked" ascii //weight: 1
        $x_1_14 = "virus" ascii //weight: 1
        $x_1_15 = "{0} MB or {1}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_9
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Telegram" ascii //weight: 10
        $x_10_2 = "Chr_0_M_e" ascii //weight: 10
        $x_1_3 = "OpenVPN" ascii //weight: 1
        $x_1_4 = "NordVPN" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
        $x_1_6 = "Discord" ascii //weight: 1
        $x_1_7 = "Scan" ascii //weight: 1
        $x_1_8 = "Password" ascii //weight: 1
        $x_1_9 = "wallet" ascii //weight: 1
        $x_1_10 = "*ssfn*" ascii //weight: 1
        $x_1_11 = "SELECT * FROM" ascii //weight: 1
        $x_1_12 = "Browser" ascii //weight: 1
        $x_1_13 = "<PreStageAction" ascii //weight: 1
        $x_1_14 = "<PassedPath" ascii //weight: 1
        $x_1_15 = "<encrypt" ascii //weight: 1
        $x_1_16 = "api.ip.sb/ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_10
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[^\\u0020-\\u007F]UNKNOWN" ascii //weight: 10
        $x_10_2 = "<PreStageAction" ascii //weight: 10
        $x_1_3 = "Discord" ascii //weight: 1
        $x_1_4 = "OpenVPN" ascii //weight: 1
        $x_1_5 = "NordVPN" ascii //weight: 1
        $x_1_6 = "Download" ascii //weight: 1
        $x_1_7 = "Scan" ascii //weight: 1
        $x_1_8 = "Password" ascii //weight: 1
        $x_1_9 = "wallet" ascii //weight: 1
        $x_1_10 = "*ssfn*" ascii //weight: 1
        $x_1_11 = "SELECT * FROM" ascii //weight: 1
        $x_1_12 = "Browser" ascii //weight: 1
        $x_1_13 = "<PassedPath" ascii //weight: 1
        $x_1_14 = "<encrypt" ascii //weight: 1
        $x_1_15 = "api.ip.sb/ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_11
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "76"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "[^\\u0020-\\u007F]UNKNOWN" ascii //weight: 50
        $x_20_2 = "ID: egram.exe" ascii //weight: 20
        $x_20_3 = "MANGO" wide //weight: 20
        $x_1_4 = "Discord" ascii //weight: 1
        $x_1_5 = "OpenVPN" ascii //weight: 1
        $x_1_6 = "NordVPN" ascii //weight: 1
        $x_1_7 = "Download" ascii //weight: 1
        $x_1_8 = "Scan" ascii //weight: 1
        $x_1_9 = "Password" ascii //weight: 1
        $x_1_10 = "wallet" ascii //weight: 1
        $x_1_11 = "*ssfn*" ascii //weight: 1
        $x_1_12 = "SELECT * FROM" ascii //weight: 1
        $x_1_13 = "Browser" ascii //weight: 1
        $x_1_14 = "<PassedPath" ascii //weight: 1
        $x_1_15 = "<encrypt" ascii //weight: 1
        $x_1_16 = "api.ip.sb/ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_12
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Telegram" ascii //weight: 10
        $x_10_2 = "[^\\u0020-\\u007F]UNKNOWN" ascii //weight: 10
        $x_1_3 = "OpenVPN" ascii //weight: 1
        $x_1_4 = "NordVPN" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
        $x_1_6 = "Discord" ascii //weight: 1
        $x_1_7 = "Scan" ascii //weight: 1
        $x_1_8 = "Password" ascii //weight: 1
        $x_1_9 = "wallet" ascii //weight: 1
        $x_1_10 = "*ssfn*" ascii //weight: 1
        $x_1_11 = "SELECT * FROM" ascii //weight: 1
        $x_1_12 = "Browser" ascii //weight: 1
        $x_1_13 = "<PreStageAction" ascii //weight: 1
        $x_1_14 = "<PassedPath" ascii //weight: 1
        $x_1_15 = "<encrypt" ascii //weight: 1
        $x_1_16 = "api.ip.sb/ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_13
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "76"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "[^\\u0020-\\u007F]UNKNOWN" ascii //weight: 50
        $x_20_2 = "ID: isSecureegram.exe" ascii //weight: 20
        $x_20_3 = "WanaLife" ascii //weight: 20
        $x_1_4 = "Discord" ascii //weight: 1
        $x_1_5 = "OpenVPN" ascii //weight: 1
        $x_1_6 = "NordVPN" ascii //weight: 1
        $x_1_7 = "Download" ascii //weight: 1
        $x_1_8 = "Scan" ascii //weight: 1
        $x_1_9 = "Password" ascii //weight: 1
        $x_1_10 = "wallet" ascii //weight: 1
        $x_1_11 = "*ssfn*" ascii //weight: 1
        $x_1_12 = "SELECT * FROM" ascii //weight: 1
        $x_1_13 = "Browser" ascii //weight: 1
        $x_1_14 = "<PassedPath" ascii //weight: 1
        $x_1_15 = "<encrypt" ascii //weight: 1
        $x_1_16 = "api.ip.sb/ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_14
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "IRemotePanel" ascii //weight: 10
        $x_10_2 = "SendClientInfo" ascii //weight: 10
        $x_1_3 = "RunPE" ascii //weight: 1
        $x_1_4 = "IClientChannel" ascii //weight: 1
        $x_1_5 = "Parse" ascii //weight: 1
        $x_1_6 = "Download" ascii //weight: 1
        $x_1_7 = "encryptedPassword" ascii //weight: 1
        $x_1_8 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_9 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_10 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_11 = "<geoplugin" ascii //weight: 1
        $x_1_12 = "VMWare" ascii //weight: 1
        $x_1_13 = "Monero" ascii //weight: 1
        $x_1_14 = "SUCK" ascii //weight: 1
        $x_1_15 = "Huflepuff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_15
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "IClientChannel" ascii //weight: 10
        $x_1_3 = ".Client.Models.Gecko" ascii //weight: 1
        $x_1_4 = "Parse" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
        $x_1_6 = "encryptedPassword" ascii //weight: 1
        $x_1_7 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_9 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_10 = "<geoplugin" ascii //weight: 1
        $x_1_11 = "VMWare" ascii //weight: 1
        $x_1_12 = "Monero" ascii //weight: 1
        $x_1_13 = "SUCK" ascii //weight: 1
        $x_1_14 = "Huflepuff" ascii //weight: 1
        $x_1_15 = ".vdfcard" ascii //weight: 1
        $x_1_16 = "T--ele--gram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_16
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "IClientChannel" ascii //weight: 10
        $x_1_3 = ".Client.Models.Gecko" ascii //weight: 1
        $x_1_4 = "Parse" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
        $x_1_6 = "encryptedPassword" ascii //weight: 1
        $x_1_7 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_9 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_10 = "<geoplugin" ascii //weight: 1
        $x_1_11 = "VMWare" ascii //weight: 1
        $x_1_12 = "Monero" ascii //weight: 1
        $x_1_13 = "SUCK" ascii //weight: 1
        $x_1_14 = "Huflepuff" ascii //weight: 1
        $x_1_15 = ".vdfcard" ascii //weight: 1
        $x_1_16 = "T--ele--gram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_17
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "IClientChannel" ascii //weight: 10
        $x_1_3 = ".Client.Models.Gecko" ascii //weight: 1
        $x_1_4 = "Parse" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
        $x_1_6 = "encryptedPassword" ascii //weight: 1
        $x_1_7 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_9 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_10 = "<geoplugin" ascii //weight: 1
        $x_1_11 = "VMWare" ascii //weight: 1
        $x_1_12 = "Monero" ascii //weight: 1
        $x_1_13 = "SUCK" ascii //weight: 1
        $x_1_14 = "Huflepuff" ascii //weight: 1
        $x_1_15 = ".vdfcard" ascii //weight: 1
        $x_1_16 = "T--ele--gram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_18
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_1_2 = {41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 [0-25] 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 6e 74 69 76 69 72 75 [0-25] 73 50 72 6f 64 75 63 74}  //weight: 1, accuracy: Low
        $x_1_4 = "Telegram" ascii //weight: 1
        $x_1_5 = "Parse" ascii //weight: 1
        $x_1_6 = "Download" ascii //weight: 1
        $x_1_7 = "Password" ascii //weight: 1
        $x_1_8 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_9 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_10 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_11 = "<geoplugin" ascii //weight: 1
        $x_1_12 = "Ethereum" ascii //weight: 1
        $x_1_13 = "Monero" ascii //weight: 1
        $x_1_14 = "wallet" ascii //weight: 1
        $x_10_15 = "Huflepuff" ascii //weight: 10
        $x_1_16 = "*.vdf" ascii //weight: 1
        $x_1_17 = "icanhazip.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_19
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "Telegram" ascii //weight: 10
        $x_1_3 = {41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 [0-25] 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {41 6e 74 69 76 69 72 75 [0-25] 73 50 72 6f 64 75 63 74}  //weight: 1, accuracy: Low
        $x_1_5 = "Parse" ascii //weight: 1
        $x_1_6 = "Download" ascii //weight: 1
        $x_1_7 = "Password" ascii //weight: 1
        $x_1_8 = {43 00 72 00 65 00 64 00 69 00 74 00 [0-4] 43 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_9 = {43 72 65 64 69 74 [0-4] 43 61 72 64}  //weight: 1, accuracy: Low
        $x_1_10 = "bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_11 = "<geoplugin" ascii //weight: 1
        $x_1_12 = "Ethereum" ascii //weight: 1
        $x_1_13 = "Monero" ascii //weight: 1
        $x_1_14 = "wallet" ascii //weight: 1
        $x_1_15 = "*.vdf" ascii //weight: 1
        $x_1_16 = "icanhazip.com" ascii //weight: 1
        $x_1_17 = "NOTMEPLEASE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GG_2147772078_20
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GG!MTB"
        threat_id = "2147772078"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_10_2 = "Telegram" ascii //weight: 10
        $x_1_3 = "Parse" ascii //weight: 1
        $x_1_4 = "Download" ascii //weight: 1
        $x_1_5 = "Password" ascii //weight: 1
        $x_1_6 = "<geoplugin" ascii //weight: 1
        $x_1_7 = "\\Electrum" ascii //weight: 1
        $x_1_8 = "\\Exodus" ascii //weight: 1
        $x_1_9 = "wallet" ascii //weight: 1
        $x_1_10 = "api.ipify.org" ascii //weight: 1
        $x_1_11 = "Coinbase" ascii //weight: 1
        $x_1_12 = "NiftyWallet" ascii //weight: 1
        $x_1_13 = {76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 [0-20] 75 00 63 00 74 00 3c 00 41 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_14 = {76 69 72 75 73 50 72 6f 64 [0-20] 75 63 74 3c 00 41 6e 74}  //weight: 1, accuracy: Low
        $x_1_15 = {72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 72 00 6f 00 [0-20] 64 00 75 00 63 00 74 00 3c 00 46 00 69 00}  //weight: 1, accuracy: Low
        $x_1_16 = {72 65 77 61 6c 6c 50 72 6f [0-20] 64 75 63 74 3c 00 46 69}  //weight: 1, accuracy: Low
        $x_1_17 = "//ipinfo.io/ip%appdata%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_RedLine_GA_2147817359_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLine.GA!MTB"
        threat_id = "2147817359"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunPE" ascii //weight: 10
        $x_1_2 = "Telegram" ascii //weight: 1
        $x_10_3 = "Chr_0_M_e" ascii //weight: 10
        $x_10_4 = "<geoplugin" ascii //weight: 10
        $x_1_5 = "Download" ascii //weight: 1
        $x_1_6 = "Password" ascii //weight: 1
        $x_1_7 = "wallet" ascii //weight: 1
        $x_1_8 = "Discord" ascii //weight: 1
        $x_1_9 = "Scan" ascii //weight: 1
        $x_1_10 = "Browser" ascii //weight: 1
        $x_1_11 = "*ssfn*" ascii //weight: 1
        $x_1_12 = "SELECT * FROM" ascii //weight: 1
        $x_1_13 = "OpenVPN" ascii //weight: 1
        $x_1_14 = "NordVPN" ascii //weight: 1
        $n_10_15 = "Microsoft." ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

