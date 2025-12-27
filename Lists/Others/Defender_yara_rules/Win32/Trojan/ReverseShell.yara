rule Trojan_Win32_ReverseShell_HNA_2147908516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReverseShell.HNA!MTB"
        threat_id = "2147908516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 83 ec 08 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 08 44 00 00 00 c7 44 24 04 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 10 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 ?? c7 44 24 10 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 ?? ?? ?? 00 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_ReverseShell_CB_2147950563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReverseShell.CB!MTB"
        threat_id = "2147950563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 2e c7 85 ?? ?? ff ff 65 78 65}  //weight: 1, accuracy: Low
        $x_2_2 = {f3 ab c7 44 24 ?? ?? ?? ?? 00 c7 44 24 ?? ?? ?? ?? 00 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 8d 85 ?? ?? ff ff 89 44 24 ?? c7 04 24 00 00 00 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ReverseShell_GXT_2147951014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReverseShell.GXT!MTB"
        threat_id = "2147951014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 85 50 fe ff ff 89 44 24 04 8b 45 f0 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 0c 85 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {ff d0 83 ec 18 89 45 f0 66 c7 85 ?? ?? ?? ?? 02 00 8b 45 f4 0f b7 c0 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 04 66 89 85 52 fe ff ff c7 04 24 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff d0 83 ec 04 89 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

