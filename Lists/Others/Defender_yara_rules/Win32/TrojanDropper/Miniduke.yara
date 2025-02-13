rule TrojanDropper_Win32_Miniduke_A_2147679575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Miniduke.A"
        threat_id = "2147679575"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniduke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TASKKILL /F /IM acro*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Miniduke_DK_2147831853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Miniduke.DK!MTB"
        threat_id = "2147831853"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniduke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 55 08 c6 42 03 3d 0f b6 45 fb 8b 4d 08 8b 55 f4 8a 04 02 88 41 02 eb 0e 8b 4d 08 c6 41 02 3d 8b 55 08 c6 42 03 3d 0f b6 45 f3 8b 4d 08 8b 55 f4 8a 04 02 88 41 01 e9}  //weight: 3, accuracy: High
        $x_2_2 = "%s%c%c%dr%ct.exe" ascii //weight: 2
        $x_2_3 = "winarc.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

