rule Trojan_Win32_Smokeldr_GP_2147787061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeldr.GP!MTB"
        threat_id = "2147787061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e8 05 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 51 8d 55 ?? 52 e8 ?? ?? ?? ?? 8b 45 ?? 50 8d 4d ?? 51 e8 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeldr_GQ_2147787226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeldr.GQ!MTB"
        threat_id = "2147787226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 36 23 01 00 01 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 8b e5 5d c2}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e9 05 89 4d ?? 8b 55 ?? 52 8d 45 ?? 50 [0-5] 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

