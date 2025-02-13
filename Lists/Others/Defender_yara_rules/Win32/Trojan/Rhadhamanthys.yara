rule Trojan_Win32_Rhadhamanthys_RPZ_2147846026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadhamanthys.RPZ!MTB"
        threat_id = "2147846026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadhamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f9 61 7c 0a 80 f9 66 7f 05 80 e9 57 eb 0d 80 f9 30 7c 0f 80 f9 39 7f 0a 80 e9 30 88 4c 14 0c 83 c2 01 83 fa 02 75 20 3b c5 73 27 8a 4c 24 0c c0 e1 04 0a 4c 24 0d 83 c0 01 88 4c 38 ff 33 d2 88 5c 24 0d 88 5c 24 0c 83 c6 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadhamanthys_RPZ_2147846026_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadhamanthys.RPZ!MTB"
        threat_id = "2147846026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadhamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 44 24 0c 8b 4c 24 28 8b 54 24 24 89 44 11 04 8b 44 24 20 8b 40 08 8b 4c 24 28 8b 54 24 24 83 c2 04 01 d1 8b 54 24 20 89 14 24 89 4c 24 04 ff d0 89 44 24 40 8a 44 24 0b 04 01 88 44 24 0b 8b 44 24 40 8b 4c 24 14 0f b6 54 24 0b 89 04 91 8b 44 24 28 8b 4c 24 24 8b 04 08 89 44 24 0c eb 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadhamanthys_RPX_2147850594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadhamanthys.RPX!MTB"
        threat_id = "2147850594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadhamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 1c 3e 8b c6 f7 74 24 18 8a 82 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e 0f b6 c0 50 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

