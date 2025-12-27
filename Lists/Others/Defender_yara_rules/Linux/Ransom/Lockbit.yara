rule Ransom_Linux_Lockbit_CD_2147930747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lockbit.CD!MTB"
        threat_id = "2147930747"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 46 b9 6b fe f7 c6 ec df f8 a0 c3 d7 e9 0e 01 dc e9 00 23 10 eb 02 0b 41 eb 03 0e 5a 46 73 46 cc e9 00 23 b8 f1 00 0f 02 d0 40 46 fe f7 16 eb}  //weight: 1, accuracy: High
        $x_1_2 = {74 49 07 f5 dc 6a d1 e9 02 23 54 1c 43 f1 00 05 d1 e9 04 23 c1 e9 02 45 da e9 00 45 a4 18 45 eb 03 09 22 46 4b 46 c1 e9 04 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Lockbit_CA_2147933283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lockbit.CA!MTB"
        threat_id = "2147933283"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 49 89 d5 53 48 89 cb 48 81 ec 48 07 00 00 4d 85 c0 48 89 bd 00 f9 ff ff 4c 89 85 08 f9 ff ff 4c 89 8d e8 f8 ff ff 4c 8b 7d 10 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {e8 fb 9f ff ff 44 8b 18 44 89 df 44 89 5c 24 1c e8 db a5 ff ff 48 89 44 24 10 e8 71 a4 ff ff 4c 8b 4c 24 10 44 8b 44 24 1c 48 8d 74 24 38 48 89 c2 89 d9 bf 80 11 61 00 31 c0 e8 d1 62 00 00 eb 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Lockbit_CE_2147945188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lockbit.CE!MTB"
        threat_id = "2147945188"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 7c 24 0c e8 33 ?? ?? ?? 31 c9 31 d2 89 c6 bf 10 00 00 00 31 c0 e8 81}  //weight: 1, accuracy: Low
        $x_2_2 = {48 89 f8 48 89 f9 8a 11 48 ff c1 83 f2 ?? 88 51 ff 84 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

