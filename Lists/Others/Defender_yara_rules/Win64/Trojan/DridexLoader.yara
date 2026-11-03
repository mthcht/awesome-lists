rule Trojan_Win64_DridexLoader_PA_2147981365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DridexLoader.PA!MTB"
        threat_id = "2147981365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DridexLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d c3 8b 45 ?? 89 c1 83 e1 1f 8b 55 ?? 8a 1c 02 8b 35 ?? ?? ?? ?? 2a 1c 0e 88 1c 02 05 ?? ?? ?? ?? 8b 4d ?? 39 c8 89 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DridexLoader_PB_2147981366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DridexLoader.PB!MTB"
        threat_id = "2147981366"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DridexLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 83 e2 1f 89 d2 41 89 d0 46 8a 0c ?? 89 c2 89 d1 4c 8b 44 24 ?? 45 8a 14 08 45 28 ca 4c 8b 5c 24 ?? 45 88 14 0b 05 ?? ?? ?? ?? 8b 54 24 ?? 39 d0 89 04 24 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

