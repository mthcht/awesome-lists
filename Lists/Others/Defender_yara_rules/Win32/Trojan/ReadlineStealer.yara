rule Trojan_Win32_ReadlineStealer_GGL_2147805542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReadlineStealer.GGL!MTB"
        threat_id = "2147805542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReadlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 38 31 fe 30 8b ?? ?? ?? ?? 01 e6 20 b1}  //weight: 10, accuracy: Low
        $x_10_2 = {11 33 31 58 12 09 56 32 14 76 05 ?? ?? ?? ?? 7b 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ReadlineStealer_BZ_2147816789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReadlineStealer.BZ!MTB"
        threat_id = "2147816789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReadlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01}  //weight: 5, accuracy: High
        $x_5_2 = {c1 e8 05 03 45 d8 c1 e1 04 03 4d e4 50 03 d6 8d 45 0c 33 ca 50}  //weight: 5, accuracy: High
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "OpenMutex" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

