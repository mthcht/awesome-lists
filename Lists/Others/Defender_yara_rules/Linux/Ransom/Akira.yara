rule Ransom_Linux_Akira_A_2147851013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akira.A!MTB"
        threat_id = "2147851013"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "akira_readme.txt" ascii //weight: 1
        $x_1_2 = "--encryption_path" ascii //weight: 1
        $x_1_3 = "--share_file" ascii //weight: 1
        $x_1_4 = ".akira" ascii //weight: 1
        $x_1_5 = "--encryption_percent" ascii //weight: 1
        $x_1_6 = {74 74 70 73 3a 2f 2f [0-88] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Akira_B_2147891813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akira.B!MTB"
        threat_id = "2147891813"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion." ascii //weight: 5
        $x_1_2 = "--encryption_path" ascii //weight: 1
        $x_1_3 = "--encryption_percent" ascii //weight: 1
        $x_1_4 = ".akira" ascii //weight: 1
        $x_1_5 = "akira_readme.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Akira_C_2147923770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akira.C!MTB"
        threat_id = "2147923770"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8d 7e 20 49 83 c6 10 e8 ad ?? ?? ?? 48 8b 7c 24 30 4c 39 f7 ?? ?? e8 a6 a0 0b 00 48 89 df e8 be ?? ?? ?? 48 8d 7d 20 48 83 c5 10 e8 89 f9 06 00 48 8b 7c 24 20 48 39 ef ?? ?? e8 82 a0 0b 00 4c 89 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 28 08 00 00 89 bd bc f7 ff ff 48 89 b5 b0 f7 ff ff 48 8d 85 00 f9 ff ff 48 89 c7 e8 0f ca 00 00 48 8b 95 b0 f7 ff ff 8b b5 bc f7 ff ff 48 8d 85 00 f9 ff ff b9 01 00 00 00 48 89 c7 e8 32 bd 00 00 48 c7 85 60 fb ff ff a3 24 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Akira_AB_2147931430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akira.AB!MTB"
        threat_id = "2147931430"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 c8 e4 91 00 c6 00 01 bf b8 e4 91 00 e8 7f f2 f6 ff ba e8 bc 64 00 be b8 e4 91 00 bf 62 57 46 00 e8 9f 61 0f 00 b8 d0 e4 91 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 89 75 f0 48 8b 45 f8 48 89 c7 e8 0d 37 fd ff 84 c0 74 13 48 8b 55 f0 48 8b 45 f8 48 89 d6 48 89 c7 e8 03 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

