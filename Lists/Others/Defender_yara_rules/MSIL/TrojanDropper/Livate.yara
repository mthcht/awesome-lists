rule TrojanDropper_MSIL_Livate_A_2147682472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Livate.A"
        threat_id = "2147682472"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Livate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ActivatorIE.exe" wide //weight: 1
        $x_1_2 = "uinfo.dat" wide //weight: 1
        $x_1_3 = "vinfo.dat" wide //weight: 1
        $x_1_4 = "WindowsLiveUpdate.exe" wide //weight: 1
        $x_1_5 = "tcookies.dat" wide //weight: 1
        $x_1_6 = "WinLive_dll_pack" wide //weight: 1
        $x_1_7 = "MToolLite.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_MSIL_Livate_B_2147689266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Livate.B"
        threat_id = "2147689266"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Livate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UID_FILE_NAME" ascii //weight: 1
        $x_1_2 = "SITES_DATA_FILE_NAME" ascii //weight: 1
        $x_1_3 = "CONFIG_DATA_FILE_NAME" ascii //weight: 1
        $x_1_4 = "SERVER_NAV_URL_TEMPLATE" ascii //weight: 1
        $x_1_5 = "TIME_COOKIES_FILE_NAME" ascii //weight: 1
        $x_1_6 = "AFFILATE_FRAME_NAME" ascii //weight: 1
        $x_1_7 = "UPDATE_INFO_FILE_NAME" ascii //weight: 1
        $x_1_8 = "PLUGIN_NEW_REG_NAME" ascii //weight: 1
        $x_1_9 = "REGEX_SIMPLIFY_URL" ascii //weight: 1
        $x_1_10 = "BHO_KEY_NAME" ascii //weight: 1
        $x_1_11 = "PLUGIN_UPDATE_URL_TEMPLATE" ascii //weight: 1
        $x_1_12 = "STARTUP_KEY" ascii //weight: 1
        $x_10_13 = "timecookies.dat" wide //weight: 10
        $x_10_14 = {4d 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 ?? ?? 75 00 70 00 64 00 61 00 74 00 65 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 ?? ?? 5c 00 62 00 28 00 3f 00 3a 00 77 00 77 00 77 00 5c 00 2e 00 29 00 3f 00 28 00 5b 00 5c 00 77 00 5c 00 64 00 5c 00 2e 00 5c 00 2d 00 5d 00 2b 00 28 00 3f 00 3a 00 5c 00 2e 00 5c 00 77 00 7b 00 32 00 2c 00 34 00 7d 00 29 00 7b 00 31 00 2c 00 32 00 7d 00 29 00 5c 00 62 00 ?? ?? 73 00 69 00 74 00 65 00 73 00 2e 00 64 00 61 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_MSIL_Livate_B_2147689266_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Livate.B"
        threat_id = "2147689266"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Livate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UID_FILE_NAME" ascii //weight: 1
        $x_1_2 = "SITES_DATA_FILE_NAME" ascii //weight: 1
        $x_1_3 = "CONFIG_DATA_FILE_NAME" ascii //weight: 1
        $x_1_4 = "SERVER_NAV_URL_TEMPLATE" ascii //weight: 1
        $x_1_5 = "TIME_COOKIES_FILE_NAME" ascii //weight: 1
        $x_1_6 = "AFFILATE_FRAME_NAME" ascii //weight: 1
        $x_1_7 = "UPDATE_INFO_FILE_NAME" ascii //weight: 1
        $x_1_8 = "PLUGIN_NEW_REG_NAME" ascii //weight: 1
        $x_1_9 = "REGEX_SIMPLIFY_URL" ascii //weight: 1
        $x_1_10 = "BHO_KEY_NAME" ascii //weight: 1
        $x_1_11 = "PLUGIN_UPDATE_URL_TEMPLATE" ascii //weight: 1
        $x_1_12 = "STARTUP_KEY" ascii //weight: 1
        $x_10_13 = "\\b(?:www\\.)?([\\w\\d\\.\\-]+(?:\\.\\w{2,4}){1,2})\\b" wide //weight: 10
        $x_10_14 = "/VersionRequest.ashx?codename={0}&version={1}&uid={2}&country={3}&browser=IE" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

