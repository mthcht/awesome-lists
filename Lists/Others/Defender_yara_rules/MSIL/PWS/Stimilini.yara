rule PWS_MSIL_Stimilini_C_2147690490_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.C"
        threat_id = "2147690490"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 67 65 74 5f 75 6d 71 75 69 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 73 65 74 5f 75 6d 71 75 69 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 67 65 74 5f 73 74 65 61 6d 49 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilini_C_2147690490_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.C"
        threat_id = "2147690490"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "get_steamID" ascii //weight: 5
        $x_1_2 = "get_friendsCount" ascii //weight: 1
        $x_1_3 = "get_unixtimestamp" ascii //weight: 1
        $x_1_4 = "set_sessionID" ascii //weight: 1
        $x_1_5 = "set_umquid" ascii //weight: 1
        $x_1_6 = "get_access_token" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_B_2147690492_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.B"
        threat_id = "2147690492"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 73 00 74 00 65 00 61 00 6d 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {09 73 00 73 00 66 00 6e 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 00 2e 00 72 00 61 00 72 00 00 11 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 2f 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 70 00 68 00 70 00 00 09 50 00 4f 00 53 00 54 00 00 0d 63 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 53 74 65 61 6d 50 61 74 68 00 53 65 6e 64 46 69 6c 65 73 00 63 6c 69 65 6e 74 5f 55 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_MSIL_Stimilini_D_2147691871_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.D"
        threat_id = "2147691871"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Valve\\Steam" ascii //weight: 1
        $x_1_2 = "\\Steam.exe" ascii //weight: 1
        $x_1_3 = "InstallPath" ascii //weight: 1
        $x_5_4 = {01 0d 09 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_10_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 56 00 61 00 6c 00 76 00 65 00 5c 00 53 00 74 00 65 00 61 00 6d 00 [0-8] 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 50 00 61 00 74 00 68 00 [0-8] 5c 00 53 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_20_6 = {2f 00 53 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 [0-8] 46 00 69 00 6c 00 65 00 20 00 69 00 73 00 20 00 63 00 6f 00 72 00 72 00 75 00 70 00 74 00 65 00 64 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_E_2147692503_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.E"
        threat_id = "2147692503"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "login" ascii //weight: 1
        $x_1_2 = "pass" ascii //weight: 1
        $x_1_3 = "set_UseSystemPasswordChar" ascii //weight: 1
        $x_1_4 = "add_KeyPress" ascii //weight: 1
        $x_5_5 = "Stearm Client" ascii //weight: 5
        $x_4_6 = {53 74 61 65 6d 00}  //weight: 4, accuracy: High
        $x_5_7 = "Va1ve Corpotation" ascii //weight: 5
        $x_6_8 = "(c) 20012-2015 Game Platform" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_E_2147692503_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.E"
        threat_id = "2147692503"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Staern.exe" ascii //weight: 1
        $x_1_2 = "get_steam64" ascii //weight: 1
        $x_1_3 = "set_SteamDir" ascii //weight: 1
        $x_1_4 = {0e 05 20 02 01 0e 0e 0a 6c 00 6f 00 67 00 69 00 6e 00 08 70 00 61 00 73 00 73 00 0a 00 05 01 0e 0e 0e 0e}  //weight: 1, accuracy: High
        $x_1_5 = {2e 52 65 73 6f 75 72 63 65 73 00 e2 [0-128] e2 80 ae 00 43 75 6c 74 75 72 65 49 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_6 = "http://5.39.124.175/files/module.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_MSIL_Stimilini_F_2147692617_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.F"
        threat_id = "2147692617"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%steamLogin" wide //weight: 1
        $x_1_2 = "tradeoffer/new/send" wide //weight: 1
        $x_1_3 = "rgInventory" wide //weight: 1
        $x_1_4 = "contextid%22%3A2%2C%22amount" wide //weight: 1
        $x_1_5 = "assetid%22%3A%22" wide //weight: 1
        $x_1_6 = "&tradeoffermessage=&json_tradeoffer=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_MSIL_Stimilini_F_2147692617_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.F"
        threat_id = "2147692617"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SteamStealer.Properties" ascii //weight: 10
        $x_1_2 = "ParseSteamCookies" ascii //weight: 1
        $x_1_3 = "FilterByRarity" ascii //weight: 1
        $x_1_4 = "sendMessageToFriends" ascii //weight: 1
        $x_1_5 = "addItemsToSteal" ascii //weight: 1
        $x_1_6 = "acceptAllIncomingTrades" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_F_2147692617_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.F"
        threat_id = "2147692617"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "login={0}&password={1}" wide //weight: 1
        $x_2_2 = "raidcallsoft.org/steam/gate.php" wide //weight: 2
        $x_1_3 = "_steam.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilini_I_2147694145_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.I"
        threat_id = "2147694145"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SteamFileStealerExtreme" ascii //weight: 5
        $x_1_2 = "GoogleChrome" ascii //weight: 1
        $x_1_3 = "PasswordData" ascii //weight: 1
        $x_1_4 = "ValveDataFormatParser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_J_2147694146_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.J"
        threat_id = "2147694146"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Steam spreader" wide //weight: 4
        $x_1_2 = "&ui_mode=web&access_token=" wide //weight: 1
        $x_1_3 = "steamLoginSecure=" wide //weight: 1
        $x_1_4 = "BlackCrypter" wide //weight: 1
        $x_1_5 = "Adding injection settings ..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_K_2147694663_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.K"
        threat_id = "2147694663"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_SLogin" ascii //weight: 1
        $x_1_2 = "get_SLogSec" ascii //weight: 1
        $x_2_3 = "KillSSFN" ascii //weight: 2
        $x_2_4 = "KillSteam" ascii //weight: 2
        $x_3_5 = "InventoryStealer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilini_L_2147695124_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.L"
        threat_id = "2147695124"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "STEAMlOGIN" ascii //weight: 3
        $x_3_2 = "$8fac72f9-1065-47bc-b350-30bac7f12009" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilini_M_2147695370_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.M"
        threat_id = "2147695370"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 70 6c 6f 61 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 72 65 61 6d 48 65 6c 70 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 65 79 6c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {56 69 63 74 69 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 74 65 61 6d 50 72 6f 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 61 73 73 77 6f 72 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_7 = {4c 6f 67 69 6e 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 74 65 61 6d 46 69 6c 65 53 74 65 61 6c 65 72 45 78 74 72 65 6d 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {46 69 72 65 66 6f 78 50 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_MSIL_Stimilini_O_2147696644_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.O"
        threat_id = "2147696644"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" wide //weight: 1
        $x_2_2 = "utilCreateResponseAndBypassServer" ascii //weight: 2
        $x_3_3 = "SteamStealer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilini_R_2147697084_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.R"
        threat_id = "2147697084"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 65 61 6d 20 53 74 65 61 6c 65 72 20 35 2e 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 65 61 6d 46 6f 6c 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 70 6c 6f 61 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 74 65 61 6d 57 6f 72 6b 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilini_T_2147707166_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilini.T"
        threat_id = "2147707166"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 65 61 6d 2e 46 6f 72 6d 73 2e 46 61 6b 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 65 61 6d 2e 65 78 65 00 53 74 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 61 6b 65 46 6f 72 6d 00 53 74 65 61 6d 2e 46 6f 72 6d 73 00 46 6f 72 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

