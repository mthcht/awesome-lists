rule Trojan_Win32_DllLoader_NEAA_2147834124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllLoader.NEAA!MTB"
        threat_id = "2147834124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b d5 41 89 96 e0 00 00 00 69 47 3c 47 c0 2c 64 3b c8 75 ec}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllLoader_CCJT_2147930877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllLoader.CCJT!MTB"
        threat_id = "2147930877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b 65 72 6e c7 05 ?? ?? ?? ?? 65 6c 33 32 c7 05 ?? ?? ?? ?? 2e 64 6c 6c c7 05 ?? ?? ?? ?? 77 69 6e 63 c7 05 ?? ?? ?? ?? 72 2e 64 6c}  //weight: 2, accuracy: Low
        $x_1_2 = {ff d6 83 ec 14 85 c0 75 ?? c7 04 24 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

