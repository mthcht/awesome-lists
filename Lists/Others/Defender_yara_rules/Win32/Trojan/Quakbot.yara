rule Trojan_Win32_Quakbot_SD_2147787511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quakbot.SD!MTB"
        threat_id = "2147787511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DllRegisterServer" ascii //weight: 3
        $x_3_2 = "stager_1" ascii //weight: 3
        $x_3_3 = "DdeDisconnectList" ascii //weight: 3
        $x_3_4 = "MBToWCSEx" ascii //weight: 3
        $x_3_5 = "DlgDirSelectExA" ascii //weight: 3
        $x_3_6 = "StrRetToBufW" ascii //weight: 3
        $x_3_7 = "DeletePrintProvidorA" ascii //weight: 3
        $x_3_8 = "SystemFunction009" ascii //weight: 3
        $x_3_9 = "HPALETTE_UserFree" ascii //weight: 3
        $x_3_10 = "joyGetThreshold" ascii //weight: 3
        $x_3_11 = "mmioRenameW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quakbot_MB_2147814735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quakbot.MB!MTB"
        threat_id = "2147814735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "aDo1geZwH.dll" ascii //weight: 3
        $x_3_2 = "AOypo" ascii //weight: 3
        $x_3_3 = "CIBWpqmj" ascii //weight: 3
        $x_3_4 = "PostMessageA" ascii //weight: 3
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_7 = "DllRegisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

