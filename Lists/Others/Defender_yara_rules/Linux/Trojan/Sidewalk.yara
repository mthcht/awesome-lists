rule Trojan_Linux_Sidewalk_D_2147935672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sidewalk.D!MTB"
        threat_id = "2147935672"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sidewalk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 bb 48 f6 09 00 00 75 ?? 68 ff 00 00 00 8d ?? ?? ?? ?? ?? ?? 56 e8 d8 03 00 00 c6 84 24 ab 01 00 00 00 5d 5a 85 c0 75 ?? 6a 2e 56 e8 38 55 ff ff 5e 5f 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {53 57 ff 74 24 64 e8 a8 52 ff ff 8b 44 24 68 01 d8 8b 54 24 6c 29 da 89 c3 f7 db 83 e3 03 29 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Sidewalk_E_2147950397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sidewalk.E!MTB"
        threat_id = "2147950397"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sidewalk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e5 93 23 4c e2 61 b0 00 e1 54 00 02 3a 00 00 31 e5 93 23 50 e5 93 33 54 e1 52 00 03 aa 00 00 2d e2 81 10 0a e0 81 10 04 e0 01 50 0b e1 54 00 05 2a 00 00 28 e5 8d 00 04 e5 8d 00 00 e3 a0 30 22 e3 a0 20 03 e1 a0 10 05 eb 00 17 a8 e3 70 00 01 0a 00 00 20 e2 10 30 07 12 63 30 08 17 a0 30 03 e5 9f 23 80 10 45 30 03 05 80 30 00 13 83 30 02 03 85 30 02 e5 80 30 04 e0 8f 20 02 e5 92 33 50 e5 92 13 58 e2 83 30 01 e1 53 00 01 c5 82 33 58 e5 82 33 50 e5 9f 33 50 e0 8f 30 03 e5 93 13 64 e5 93 23 70 e0 85 10 01}  //weight: 1, accuracy: High
        $x_1_2 = {e1 53 00 07 8a 00 00 1f e5 9a 80 04 e0 47 70 03 e3 58 00 00 1a 00 00 12 e3 a0 0e 2f eb ff d4 96 e3 50 00 00 e1 a0 40 00 e5 8a 00 04 1a 00 00 0e e5 9f 30 80 e5 9f 10 80 e7 96 20 03 e0 8f 10 01 e5 92 30 00 e2 83 30 01 e5 82 30 00 e5 9f 30 6c e7 96 30 03 e5 93 00 00 eb 00 02 af e3 a0 00 7f eb ff fb 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

