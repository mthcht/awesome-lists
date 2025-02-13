rule Ransom_Win64_Azov_B_2147834903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Azov.B"
        threat_id = "2147834903"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Azov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 78 00 65 00 00 00 00 00 ?? 00 00 00 2e 00 61 00 7a 00 6f 00 76}  //weight: 1, accuracy: Low
        $x_1_2 = {42 00 61 00 6e 00 64 ?? 65 00 72 00 61}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 45 00 53 00 54 00 4f 00 52 00 45 00 5f 00 46 00 49 ?? 4c 00 45 00 53 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Azov_2147837905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Azov.psyA!MTB"
        threat_id = "2147837905"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Azov"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {ff d0 48 c7 c1 ?? ?? ?? 00 4c 8d 0d ?? ?? ?? ff 48 ff c9 41 8a 14 09 88 14 08 48 85 c9 75 f1 48 c7 c1 ?? ?? ?? 00 41 b9 ?? ?? ?? 00 41 ba 00 92 81 92 48 ff c9 8a 14 08 44 30 ca 88 14 08 41 81 ea e2 6f 02 00 45 01 d1 41 81 c1 e2 6f 02 00 41 81 c2 e2 6f 02 00 41 d1 c1 48 85 c9 75 0b 74 0f e8 fb ff ff ff df 6f 84 e9 75 c7 f3 34 01 00 75 81}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

