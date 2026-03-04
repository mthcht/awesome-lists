rule Trojan_Win64_Dapato_NA_2147950686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.NA!MTB"
        threat_id = "2147950686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4c 63 25 8f cd 0f 00 41 8d 4c 24 01 48 63 c9 48 c1 e1 03 e8 56 93 01 00 49 89 c5 48 85 c0 74 57}  //weight: 2, accuracy: High
        $x_1_2 = {e8 73 92 01 00 4c 8b 05 5c cf 0f 00 8b 0d 66 cf 0f 00 4c 89 00 48 8b 15 54 cf 0f 00 e8 f7 ba 0c 00 8b 0d 39 cf 0f 00 85 c9 0f 84 fb 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dapato_SX_2147964062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.SX!MTB"
        threat_id = "2147964062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 45 03 c5 4d 03 cd 41 83 f8}  //weight: 10, accuracy: Low
        $x_10_2 = {41 f7 e0 c1 ea ?? 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 45 03 c4 4d 03 cc 41 83 f8}  //weight: 10, accuracy: Low
        $x_50_3 = {48 33 d8 48 89 5d ?? 48 c7 01 00 00 00 00 33 c9 48 8d 15 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 2e}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

