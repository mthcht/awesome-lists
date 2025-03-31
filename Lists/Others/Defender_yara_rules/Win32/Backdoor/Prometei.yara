rule Backdoor_Win32_Prometei_GTZ_2147937184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prometei.GTZ!MTB"
        threat_id = "2147937184"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 02 88 1c 06 88 0c 02 0f b6 1c 06 0f b6 c9 03 d9 81 e3 ?? ?? ?? ?? ?? ?? 4b 81 cb ?? ?? ?? ?? 43 8a 0c 03 8b 5d ?? 32 0c 3b 47 83 6d ?? 01 88 4f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prometei_GTX_2147937377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prometei.GTX!MTB"
        threat_id = "2147937377"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 44 45 4c 33 32 2e 44 4c 4c 00 00 57 49 4e 49 4e 45 3c 61 ?? ?? 2c ?? 41 c1 c9 ?? 41 01 c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

