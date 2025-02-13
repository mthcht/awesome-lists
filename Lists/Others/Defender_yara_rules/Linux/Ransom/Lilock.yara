rule Ransom_Linux_Lilock_B_2147796725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lilock.B!MTB"
        threat_id = "2147796725"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lilock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 06 83 f2 36 88 14 04 48 ff c0 48 3d 80 00 00 00 75 ?? 48 89 cf e8 ?? ?? ?? ?? 48 89 e6 ba 80 00 00 00 e8 ?? ?? ?? ?? 48 83 ec 80 c3}  //weight: 2, accuracy: Low
        $x_1_2 = {40 0f b6 d6 40 8a b0 ?? ?? ?? ?? 8a 81 ?? ?? ?? ?? 44 89 c1 8a 92 ?? ?? ?? ?? c1 e9 03 44 32 89 ?? ?? ?? ?? 44 88 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 f3 48 01 f5 b8 10 00 00 00 48 83 ec 10 48 39 eb 74 ?? 83 f8 10 75 ?? 41 0f 10 84 24 f0 00 00 00 4c 89 e6 48 89 e7 0f 11 04 24 e8 ?? ?? ?? ?? b8 0f 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Lilock_C_2147891159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lilock.C!MTB"
        threat_id = "2147891159"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lilock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 9b 82 30 e0 e7 7a 83 44 39 34 dc 14 b4 74 04 10 d2 f2 49 ac 4a 18 6a a3 28 de 1a 83 c9 a3 d5 1c 11 a0 6c d8 e3 11 0d 2e 94 71 84 c2 4d c4 4e da 2e 81 74 1b 25 87 60 c0 54 88 4b 86 5d f9 58 08 3a b5 eb ec cf 2e 51 ea bb 00 3a 9b 78 01 1b 8b 93 2f 5a b0 0f 0b 85 d2 29 57 e1 55 19 20 56 3c a1 da 06 41 ab 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

