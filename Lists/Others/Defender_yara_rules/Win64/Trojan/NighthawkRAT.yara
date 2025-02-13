rule Trojan_Win64_NighthawkRAT_PB_2147836876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NighthawkRAT.PB!MTB"
        threat_id = "2147836876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NighthawkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c8 48 8b c1 48 89 44 24 ?? b8 08 00 00 00 48 6b c0 00 48 8b 4c 24 ?? 8b 84 01 ?? ?? ?? ?? 89 44 24 ?? 83 7c 24 [0-6] 75 ?? 33 c0 e9 [0-4] 8b 44 24 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 ?? 48 8b 44 24 ?? 83 78 [0-4] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 03 c8 48 8b c1 48 89 84 24 [0-4] 48 8b 44 24 ?? 8b 40 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 ?? 48 8b 44 24 ?? 8b 40 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 84 24 [0-4] c7 44 24 [0-6] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NighthawkRAT_PA_2147840757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NighthawkRAT.PA!MTB"
        threat_id = "2147840757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NighthawkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 48 8d 0d [0-6] 51 5a 48 81 c1 [0-6] 48 81 c2 [0-6] ff e2}  //weight: 1, accuracy: Low
        $x_1_2 = {66 03 d2 66 33 d1 66 c1 e2 02 66 33 d1 66 23 d0 0f b7 c1 0f 5f d2 99 91 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

