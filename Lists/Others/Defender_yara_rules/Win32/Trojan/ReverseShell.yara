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

