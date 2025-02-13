rule Ransom_Linux_RansomExx_A_2147810327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RansomExx.A!MTB"
        threat_id = "2147810327"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RansomExx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 45 f8 48 01 d0 48 be 21 4e 45 57 53 5f 46 4f 48 bf 52 5f 53 54 4a 21 2e 74 48 89 30 48 89 78 08 66 c7 40 10 78 74 c6 40 12 00 48 8d 95 60 ff ff ff 48 8b 45 f8 48 89 d6 48 89 c7 e8 bd eb 01 00 83 f8 ff 74 0f 48 8b 45 f8 48 89 c7 e8 7c ea ff ff eb 01}  //weight: 2, accuracy: High
        $x_2_2 = {48 01 d0 48 be 21 4e 45 57 53 5f 46 4f 48 bf 52 5f [0-32] 78 74 c6 40 ?? 00 48 8d 95 60 ff ff ff 48 8b 45 f8 48 89 d6 48 89 c7 e8 ?? ed 01 00 83 f8 ff 75 4c 48 8b 45 f8 48 8d 35 ?? ff 01 00 48 89 c7 e8 ?? ed ff ff 48 89 45 f0 48 83 7d f0 00 74 31 48 8b 45 f0 48 89 c1 ba ?? ?? 00 00 be 01 00 00 00 48 8d 3d ?? ff 01 00 e8 ?? ed ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = "CryptOneFile" ascii //weight: 1
        $x_1_4 = "CryptOneBlock" ascii //weight: 1
        $x_1_5 = "ReadMeStoreForDir" ascii //weight: 1
        $x_1_6 = "GetRansomConfig" ascii //weight: 1
        $x_1_7 = "!NEWS_FOR_EIGSI!.txt" ascii //weight: 1
        $x_1_8 = "Yours information is securely ENCRYPTED" ascii //weight: 1
        $x_1_9 = "BFC02A208B37E9B96A9ABFFCCED1086B8865B672540E54B0EBD9811F87C4EEE14B99BEAD988" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_RansomExx_B_2147810328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RansomExx.B!MTB"
        threat_id = "2147810328"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RansomExx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c7 e8 a7 1b 00 00 89 45 cc 83 7d cc 00 0f 85 6f 01 00 00 48 8d 85 70 ee ff ff 48 83 c0 10 48 8d 15 10 0a 02 00 be 10 00 00 00 48 89 c7 e8 2d 14 01 00 89 45 cc 83 7d cc 00 0f 85 46 01 00 00 48 8d 85 70 ee ff ff 48 83 c0 28 48 8d 15 e5 0d 02 00 be 10 00 00 00 48 89 c7 e8 01 14 01 00 89 45 cc 83 7d cc 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 01 d0 48 be 58 58 58 58 58 58 58 58 58 bf 58 58 58 58 58 58 58 58 58 89 30 48 89 78 08 c7 40 10 58 58 58 58 c6 40 14 00 48 8d 95 60 ff ff ff 48 8b 45 f8 48 89 d6 48 89 c7 e8 18 ed 01 00 83 f8 ff 75 4c 48 8b 45 f8 48 8d 35 a0 ff 01 00 48 89 c7 e8 50 ed ff ff 48 89 45 f0 48 83 7d f0 00 74 31 48 8b 45 f0 48 89 c1 ba ec 01 00 00 be 01 00 00 00 48 8d 3d 7d ff 01 00 e8 d8 ed ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {48 be 58 58 58 58 58 58 58 58 58 bf 58 58 58 58 58 58 58 58 58 89 30 48 89 78 08 c7 40 10 58 58 58 58 c6 40 14 00 48 8d 95 60 ff ff ff 48 8b 45 f8 48 89 d6 48 89 c7 e8 c8 eb 01 00 83 f8 ff 74 0f 48 8b 45 f8 48 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

