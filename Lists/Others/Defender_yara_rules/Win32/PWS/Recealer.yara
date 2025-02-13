rule PWS_Win32_Recealer_GKM_2147777164_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Recealer.GKM!MTB"
        threat_id = "2147777164"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Recealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 3b c6 76 ?? 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 88 14 0f 3d 03 02 00 00 75 06 89 35 ?? ?? ?? ?? 41 3b c8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Recealer_GKM_2147777164_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Recealer.GKM!MTB"
        threat_id = "2147777164"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Recealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 05 89 74 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

