rule Trojan_Win32_BatchWiper_MA_2147839832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BatchWiper.MA!MTB"
        threat_id = "2147839832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BatchWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 f8 81 c2 00 40 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 05 50 8b 0d ?? ?? ?? ?? 51 6a 01 8b 15 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 0c 89 45 fc 8b 4d 0c 03 4d 08 89 0d b0 b3 40 00 8b 45 fc 8b e5 5d c2}  //weight: 5, accuracy: Low
        $x_5_2 = ".tmp\\DreS_X.bat" ascii //weight: 5
        $x_1_3 = "taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_4 = "Please enter the password." ascii //weight: 1
        $x_1_5 = "@echo off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

