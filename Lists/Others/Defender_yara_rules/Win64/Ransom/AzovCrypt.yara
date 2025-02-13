rule Ransom_Win64_AzovCrypt_PA_2147835478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AzovCrypt.PA!MTB"
        threat_id = "2147835478"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AzovCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 c1 e0 3f 00 00 41 b9 13 5c 01 00 41 ba 00 92 81 92 48 ff c9 8a 14 08 44 30 ca 88 14 08 41 81 ea e2 6f 02 00 45 01 d1 41 81 c1 e2 6f 02 00 41 81 c2 e2 6f 02 00 41 d1 c1 48 85 c9 75 [0-4] 74 [0-4] e8 [0-16] e9 [0-4] 01 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_AzovCrypt_PB_2147835568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AzovCrypt.PB!MTB"
        threat_id = "2147835568"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AzovCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {57 48 83 ec 50 48 8d 05 [0-4] 48 8b f1 49 89 43 ?? 49 8d 7b ?? 48 8d 05 [0-4] 33 db 49 89 43 ?? 48 8d 05 [0-4] 49 89 43 ?? 48 8d 05 [0-4] 49 89 43 ?? 48 8d 05 [0-4] 49 89 43}  //weight: 10, accuracy: Low
        $x_10_3 = {48 8b 41 08 48 8b 09 ff [0-4] 3d 9a 02 00 00 0f 85 [0-4] 48 8b [0-6] 48 8d [0-6] 33 c9 45 33 c9 48 89 4c 24 [0-2] 45 33 c0 48 89 8c 24 [0-4] 4c 8b 10 48 8d 84 24 [0-4] 48 89 44 24 ?? 48 89 4c 24 ?? 48 c7 44 24 [0-6] 48 89 4c 24 ?? 48 c7 c1 [0-4] 41 ff [0-6] 48 85 c0 75 ?? 48 8b [0-6] 48 8d 8c 24 [0-4] 4c 8b 10 48 83 [0-16] 66 83 [0-4] 48 8d 40 01 75 [0-4] 48 8b 8c 24 [0-4] 48 8d 04 45 [0-4] 48 89 [0-4] 48 8d 15 [0-4] 48 8d 84 24 [0-4] 41 b9 [0-4] 45 33 c0 48 89 44 24 ?? 41 ff 92 [0-4] 48 8b 8c 24 [0-4] 48 85 c9 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

