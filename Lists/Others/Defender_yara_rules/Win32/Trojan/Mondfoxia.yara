rule Trojan_Win32_Mondfoxia_2147766233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mondfoxia!MTB"
        threat_id = "2147766233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mondfoxia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8d 34 03 e8 ?? ?? ?? ?? 30 06 b8 ?? ?? ?? ?? 29 45 ?? 39 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mondfoxia_2147766233_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mondfoxia!MTB"
        threat_id = "2147766233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mondfoxia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 18 e8 ?? ?? ?? ?? 30 06 b8 ?? ?? ?? ?? 29 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

