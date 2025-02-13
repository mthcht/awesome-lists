rule PWS_Win32_Spynoon_DLG_2147787479_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Spynoon.DLG!MTB"
        threat_id = "2147787479"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 13 89 42 01 8b 03 8b 16 89 50 05 8b 03 89 06 83 03 0d 8b 03 2b 45 f8 3d fc 0f 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "GetKeyboardType" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_5 = "EActnList" ascii //weight: 1
        $x_1_6 = "WWinSpool" ascii //weight: 1
        $x_1_7 = "e-mail ig_zub@ukr.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Spynoon_STR_2147787480_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Spynoon.STR!MTB"
        threat_id = "2147787480"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T__23f3040U" ascii //weight: 1
        $x_1_2 = "T__23f3150U" ascii //weight: 1
        $x_1_3 = "RHelpIntfs" ascii //weight: 1
        $x_1_4 = "5MaskUtils" ascii //weight: 1
        $x_1_5 = "RT__23f2e20U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

